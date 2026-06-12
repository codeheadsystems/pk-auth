// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import com.codeheadsystems.pkauth.backupcodes.BackupCodeService;
import com.codeheadsystems.pkauth.ceremony.InMemoryCeremonyRateLimiter;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.config.CeremonyConfig;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.jwt.AccessTokenStore;
import com.codeheadsystems.pkauth.jwt.AccessTokenStoreDeletionListener;
import com.codeheadsystems.pkauth.jwt.JwtConfig;
import com.codeheadsystems.pkauth.jwt.JwtKeyset;
import com.codeheadsystems.pkauth.jwt.JwtSecretResolver;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.jwt.RevocationCheck;
import com.codeheadsystems.pkauth.lifecycle.BackupCodeRepositoryDeletionListener;
import com.codeheadsystems.pkauth.lifecycle.CredentialRepositoryDeletionListener;
import com.codeheadsystems.pkauth.lifecycle.OtpRepositoryDeletionListener;
import com.codeheadsystems.pkauth.lifecycle.UserDeletionListener;
import com.codeheadsystems.pkauth.lifecycle.UserDeletionService;
import com.codeheadsystems.pkauth.magiclink.EmailSender;
import com.codeheadsystems.pkauth.magiclink.LoggingEmailSender;
import com.codeheadsystems.pkauth.magiclink.MagicLinkService;
import com.codeheadsystems.pkauth.otp.LoggingSmsSender;
import com.codeheadsystems.pkauth.otp.OtpPepperResolver;
import com.codeheadsystems.pkauth.otp.OtpService;
import com.codeheadsystems.pkauth.otp.SmsSender;
import com.codeheadsystems.pkauth.refresh.RefreshTokenConfig;
import com.codeheadsystems.pkauth.refresh.RefreshTokenService;
import com.codeheadsystems.pkauth.refresh.RefreshTokenServiceDeletionListener;
import com.codeheadsystems.pkauth.refresh.spi.RefreshTokenRepository;
import com.codeheadsystems.pkauth.refresh.web.RefreshHandler;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.CeremonyRateLimiter;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Requires;
import jakarta.inject.Singleton;
import java.util.ArrayList;
import java.util.Collection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Wires every pk-auth service Micronaut hosts. Persistence SPIs ({@link CredentialRepository},
 * {@link UserLookup}, {@link ChallengeStore}, {@link BackupCodeRepository}, {@link OtpRepository})
 * must be supplied by the host application or by including {@code pk-auth-persistence-jdbi} /
 * {@code pk-auth-persistence-dynamodb} with their own factories.
 */
@Factory
public class PkAuthFactory {

  private static final Logger LOG = LoggerFactory.getLogger(PkAuthFactory.class);

  @Singleton
  RelyingPartyConfig relyingPartyConfig(PkAuthConfiguration config) {
    PkAuthConfiguration.RelyingParty rp = config.getRelyingParty();
    return RelyingPartyConfig.from(rp.getId(), rp.getName(), rp.getOrigins());
  }

  @Singleton
  CeremonyConfig ceremonyConfig(PkAuthConfiguration config) {
    // Only challengeTtl is host-settable here; the remaining knobs take the conservative core
    // defaults (UV=REQUIRED, counter=REJECT) via the null fallbacks.
    return CeremonyConfig.from(config.getCeremony().getChallengeTtl(), null, null, null, null);
  }

  @Singleton
  ClockProvider clockProvider() {
    return ClockProvider.system();
  }

  @Singleton
  JwtConfig jwtConfig(PkAuthConfiguration config) {
    PkAuthConfiguration.Jwt jwt = config.getJwt();
    String issuer = jwt.getIssuer();
    String audience = jwt.getAudience();
    if (issuer == null || issuer.isBlank() || audience == null || audience.isBlank()) {
      throw new IllegalStateException(
          "pkauth.jwt.{issuer,audience} are required. Set them explicitly in configuration —"
              + " there are no defaults.");
    }
    return JwtConfig.from(issuer, audience, jwt.getDefaultTtl(), jwt.getTtlsByAudience());
  }

  @Singleton
  JwtKeyset jwtKeyset(PkAuthConfiguration config) {
    return JwtSecretResolver.resolveHs256Keyset(config.getJwt().getSecret());
  }

  /**
   * Default no-op {@link AccessTokenStore}. Hosts wanting stateful access tokens replace this bean
   * by declaring their own {@code @Singleton AccessTokenStore} in their factory.
   *
   * @since 1.1.0
   */
  @Singleton
  AccessTokenStore accessTokenStore() {
    return AccessTokenStore.noop();
  }

  @Singleton
  PkAuthJwtIssuer jwtIssuer(
      JwtConfig cfg, JwtKeyset keyset, ClockProvider clock, AccessTokenStore accessTokenStore) {
    return new PkAuthJwtIssuer(cfg, keyset, clock, accessTokenStore);
  }

  /**
   * Shared ceremony orchestrator — JWT mint + label lookup + wire mapping. Lives in {@code
   * pk-auth-jwt} so every adapter holds a single dependency rather than three.
   *
   * @since 0.9.1
   */
  @Singleton
  com.codeheadsystems.pkauth.jwt.CeremonyOrchestrator ceremonyOrchestrator(
      PasskeyAuthenticationService service,
      PkAuthJwtIssuer issuer,
      CredentialRepository credentialRepository) {
    return com.codeheadsystems.pkauth.composition.PkAuthComposition.ceremonyOrchestrator(
        service, issuer, credentialRepository);
  }

  @Singleton
  PkAuthJwtValidator jwtValidator(
      JwtConfig cfg, JwtKeyset keyset, ClockProvider clock, AccessTokenStore accessTokenStore) {
    return new PkAuthJwtValidator(cfg, keyset, clock, RevocationCheck.allow(), accessTokenStore);
  }

  // -- User deletion fan-out ---------------------------------------------------------------

  @Singleton
  UserDeletionListener credentialDeletionListener(CredentialRepository repo) {
    return new CredentialRepositoryDeletionListener(repo);
  }

  @Singleton
  UserDeletionListener backupCodeDeletionListener(BackupCodeRepository repo) {
    return new BackupCodeRepositoryDeletionListener(repo);
  }

  @Singleton
  UserDeletionListener otpDeletionListener(OtpRepository repo) {
    return new OtpRepositoryDeletionListener(repo);
  }

  @Singleton
  UserDeletionListener accessTokenStoreDeletionListener(AccessTokenStore store) {
    return new AccessTokenStoreDeletionListener(store);
  }

  @Singleton
  UserDeletionService userDeletionService(Collection<UserDeletionListener> listeners) {
    return new UserDeletionService(new ArrayList<>(listeners));
  }

  // -- Refresh tokens (only active when a RefreshTokenRepository bean is wired) ----------------

  @Singleton
  RefreshTokenConfig refreshTokenConfig(PkAuthConfiguration config) {
    PkAuthConfiguration.Refresh refresh = config.getRefresh();
    return RefreshTokenConfig.from(
        refresh.getDefaultTtl(), refresh.getTtlsByAudience(), refresh.getCleanupRetention());
  }

  @Singleton
  @Requires(beans = RefreshTokenRepository.class)
  RefreshTokenService refreshTokenService(
      RefreshTokenRepository repository, RefreshTokenConfig config, ClockProvider clockProvider) {
    return new RefreshTokenService(repository, config, clockProvider);
  }

  @Singleton
  @Requires(beans = RefreshTokenService.class)
  UserDeletionListener refreshTokenServiceDeletionListener(RefreshTokenService service) {
    return new RefreshTokenServiceDeletionListener(service);
  }

  @Singleton
  @Requires(beans = RefreshTokenService.class)
  RefreshHandler refreshHandler(RefreshTokenService service, PkAuthJwtIssuer issuer) {
    return new RefreshHandler(service, issuer);
  }

  /**
   * Default in-memory {@link CeremonyRateLimiter} — hosts running more than one replica MUST supply
   * a shared (Redis / DB-backed) bean to replace this. See {@link InMemoryCeremonyRateLimiter}
   * javadoc.
   *
   * @since 0.9.1
   */
  @Singleton
  CeremonyRateLimiter ceremonyRateLimiter() {
    return new InMemoryCeremonyRateLimiter();
  }

  @Singleton
  PasskeyAuthenticationService ceremonyService(
      CredentialRepository credentialRepository,
      UserLookup userLookup,
      ChallengeStore challengeStore,
      RelyingPartyConfig rp,
      CeremonyConfig ceremonyConfig,
      ClockProvider clock,
      CeremonyRateLimiter rateLimiter) {
    return com.codeheadsystems.pkauth.composition.PkAuthComposition.passkeyAuthenticationService(
        credentialRepository, userLookup, challengeStore, clock, rp, ceremonyConfig, rateLimiter);
  }

  @Singleton
  BackupCodeService backupCodeService(BackupCodeRepository repo, ClockProvider clock) {
    return BackupCodeService.create(BackupCodeService.Dependencies.of(repo, clock));
  }

  /**
   * Logging senders are dev-only: they write magic-link tokens / OTP codes to the application log.
   * They activate only when {@code pkauth.dev-mode=true}; otherwise a host must supply real {@code
   * EmailSender} / {@code SmsSender} beans.
   */
  @Singleton
  @Requires(property = "pkauth.dev-mode", value = "true")
  EmailSender emailSender() {
    LOG.error(
        "pkauth.dev-mode=true: using LoggingEmailSender — magic-link tokens will be written to"
            + " the application log. DO NOT use in production.");
    return new LoggingEmailSender();
  }

  @Singleton
  @Requires(property = "pkauth.dev-mode", value = "true")
  SmsSender smsSender() {
    LOG.error(
        "pkauth.dev-mode=true: using LoggingSmsSender — OTP codes will be written to the"
            + " application log. DO NOT use in production.");
    return new LoggingSmsSender();
  }

  @Singleton
  MagicLinkService magicLinkService(
      PkAuthJwtIssuer issuer,
      PkAuthJwtValidator validator,
      EmailSender emailSender,
      UserLookup userLookup,
      ClockProvider clock) {
    return MagicLinkService.create(
        MagicLinkService.Dependencies.of(issuer, validator, emailSender, userLookup, clock),
        "http://localhost:8080/auth/magic");
  }

  @Singleton
  OtpService otpService(
      OtpRepository repo, SmsSender sms, ClockProvider clock, PkAuthConfiguration config) {
    byte[] pepper = OtpPepperResolver.resolve(() -> config.getOtp().getPepper(), config::isDevMode);
    return OtpService.create(OtpService.Dependencies.of(repo, sms, clock), pepper);
  }

  // The optional admin service lives in PkAuthAdminFactory, which is gated with
  // @Requires(classes = AdminService.class). Keeping it off this factory means PkAuthFactory holds
  // no reference to the compileOnly pk-auth-admin-api module, so a host that omits that module can
  // still build the ceremony / JWT beans here without a NoClassDefFoundError on the admin types.
}
