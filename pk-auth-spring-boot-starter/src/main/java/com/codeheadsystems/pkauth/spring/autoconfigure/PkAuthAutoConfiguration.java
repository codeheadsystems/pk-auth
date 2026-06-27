// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.autoconfigure;

import com.codeheadsystems.pkauth.backupcodes.BackupCodeService;
import com.codeheadsystems.pkauth.ceremony.InMemoryCeremonyRateLimiter;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.composition.PkAuthComposition;
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
import com.codeheadsystems.pkauth.spring.config.PkAuthProperties;
import com.codeheadsystems.pkauth.testkit.InMemoryBackupCodeRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryChallengeStore;
import com.codeheadsystems.pkauth.testkit.InMemoryCredentialRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryOtpRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryUserLookup;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Top-level autoconfiguration for the pk-auth Spring Boot starter. Wires:
 *
 * <ul>
 *   <li>Core service ({@code PasskeyAuthenticationService}) via the {@link PkAuthComposition}
 *       framework-neutral wiring helper.
 *   <li>SPI implementations — {@code CredentialRepository} / {@code UserLookup} / {@code
 *       ChallengeStore} / {@code BackupCodeRepository} / {@code OtpRepository}. Each is provided
 *       only when no host-app bean of the same type exists ({@link ConditionalOnMissingBean}) AND
 *       the host has explicitly opted in to the in-memory testkit defaults by setting {@code
 *       pkauth.dev-mode=true}. Without that flag, a host that fails to declare its own SPI beans
 *       will fail to start — preventing accidental production deploys backed by single-JVM,
 *       non-persistent storage. Host apps that want JDBI or DynamoDB declare those beans themselves
 *       (typically in their own {@code @Configuration}).
 *   <li>JWT issuer + validator backed by {@link JwtKeyset#hs256(byte[])}. {@code pkauth.jwt.secret}
 *       is required — there is no random-key fallback. Hosts that need ES256 supply a {@code
 *       JwtKeyset} bean themselves.
 *   <li>Default sender beans ({@link LoggingEmailSender}, {@link LoggingSmsSender}) so the alt-flow
 *       services compose. Per brief §12 #7, "Don't write production-quality email/SMS senders" —
 *       the logging shims are deliberate.
 * </ul>
 *
 * <p>Web-tier wiring (the ceremony controller, JWT filter, admin controller) lives in {@link
 * PkAuthWebAutoConfiguration} so this class can stay focused on the framework-neutral surface.
 *
 * <p>The brief (§4.2) calls for an explicit guard against Spring Security's own webauthn module.
 * That guard lives in {@link PkAuthWebAutoConfiguration} where it has access to the security filter
 * chain.
 */
@AutoConfiguration
@EnableConfigurationProperties(PkAuthProperties.class)
public class PkAuthAutoConfiguration {

  private static final Logger LOG = LoggerFactory.getLogger(PkAuthAutoConfiguration.class);

  // -- Core wiring -----------------------------------------------------------------------------

  @Bean
  @ConditionalOnMissingBean
  public ClockProvider pkAuthClockProvider() {
    return ClockProvider.system();
  }

  @Bean
  @ConditionalOnMissingBean
  public RelyingPartyConfig pkAuthRelyingPartyConfig(PkAuthProperties props) {
    PkAuthProperties.RelyingParty rp = props.relyingParty();
    return rp == null
        ? RelyingPartyConfig.from(null, null, null)
        : RelyingPartyConfig.from(rp.id(), rp.name(), rp.origins());
  }

  @Bean
  @ConditionalOnMissingBean
  public CeremonyConfig pkAuthCeremonyConfig(PkAuthProperties props) {
    PkAuthProperties.Ceremony c = props.ceremony();
    // Every knob falls back to the framework-neutral core defaults (UV=REQUIRED, counter=REJECT),
    // not weaker adapter-local values — a host must opt in explicitly to relax any of them.
    return CeremonyConfig.from(
        c.challengeTtl(),
        c.userVerification(),
        c.residentKey(),
        c.attestation(),
        c.counterRegression(),
        c.offeredAlgorithms(),
        c.acceptedAlgorithms());
  }

  /**
   * Logged once on bean creation when the dev-mode testkit defaults activate, so an operator who
   * trips this in production sees it loudly in startup logs.
   */
  private static final String DEV_MODE_WARNING =
      "pkauth.dev-mode=true: using in-memory testkit SPI for {} — DO NOT use in production. "
          + "State is per-JVM and lost on restart.";

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "pkauth", name = "dev-mode", havingValue = "true")
  public CredentialRepository pkAuthCredentialRepository() {
    LOG.warn(DEV_MODE_WARNING, "credentials");
    return new InMemoryCredentialRepository();
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "pkauth", name = "dev-mode", havingValue = "true")
  public UserLookup pkAuthUserLookup() {
    LOG.warn(DEV_MODE_WARNING, "users");
    return new InMemoryUserLookup();
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "pkauth", name = "dev-mode", havingValue = "true")
  public ChallengeStore pkAuthChallengeStore() {
    LOG.warn(DEV_MODE_WARNING, "challenges");
    return new InMemoryChallengeStore();
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "pkauth", name = "dev-mode", havingValue = "true")
  public BackupCodeRepository pkAuthBackupCodeRepository() {
    LOG.warn(DEV_MODE_WARNING, "backup-codes");
    return new InMemoryBackupCodeRepository();
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "pkauth", name = "dev-mode", havingValue = "true")
  public OtpRepository pkAuthOtpRepository() {
    LOG.warn(DEV_MODE_WARNING, "otp");
    return new InMemoryOtpRepository();
  }

  /**
   * Default in-memory ceremony rate limiter. Hosts MUST replace this with a shared (Redis /
   * DB-backed) {@link CeremonyRateLimiter} bean in multi-replica deployments — see {@link
   * InMemoryCeremonyRateLimiter}'s class javadoc.
   *
   * @since 0.9.1
   */
  @Bean
  @ConditionalOnMissingBean
  public CeremonyRateLimiter pkAuthCeremonyRateLimiter() {
    return new InMemoryCeremonyRateLimiter();
  }

  @Bean
  @ConditionalOnMissingBean
  public PasskeyAuthenticationService pkAuthService(
      CredentialRepository credentialRepository,
      UserLookup userLookup,
      ChallengeStore challengeStore,
      ClockProvider clockProvider,
      RelyingPartyConfig rp,
      CeremonyConfig ceremonyConfig,
      CeremonyRateLimiter ceremonyRateLimiter) {
    return PkAuthComposition.passkeyAuthenticationService(
        credentialRepository,
        userLookup,
        challengeStore,
        clockProvider,
        rp,
        ceremonyConfig,
        ceremonyRateLimiter);
  }

  // -- JWT -------------------------------------------------------------------------------------

  @Bean
  @ConditionalOnMissingBean
  public JwtConfig pkAuthJwtConfig(PkAuthProperties props) {
    PkAuthProperties.Jwt jwt = requireJwt(props);
    return JwtConfig.from(jwt.issuer(), jwt.audience(), jwt.defaultTtl(), jwt.ttlsByAudience());
  }

  @Bean
  @ConditionalOnMissingBean
  public JwtKeyset pkAuthJwtKeyset(PkAuthProperties props) {
    PkAuthProperties.Jwt jwt = requireJwt(props);
    return JwtSecretResolver.resolveHs256Keyset(jwt.secret());
  }

  private static PkAuthProperties.Jwt requireJwt(PkAuthProperties props) {
    PkAuthProperties.Jwt jwt = props.jwt();
    if (jwt == null) {
      throw new IllegalStateException(
          "pkauth.jwt.{issuer,audience,secret} are required. Set them explicitly in configuration"
              + " — there are no defaults.");
    }
    return jwt;
  }

  /**
   * Default no-op {@link AccessTokenStore}. Hosts that want server-side access-token revocation
   * override this bean by declaring their own {@code AccessTokenStore} (e.g. {@code
   * JdbiAccessTokenStore}).
   */
  @Bean
  @ConditionalOnMissingBean
  public AccessTokenStore pkAuthAccessTokenStore() {
    return AccessTokenStore.noop();
  }

  /**
   * Default no-op {@link RevocationCheck}. Same override pattern as {@link
   * #pkAuthAccessTokenStore()}.
   */
  @Bean
  @ConditionalOnMissingBean
  public RevocationCheck pkAuthRevocationCheck() {
    return RevocationCheck.allow();
  }

  @Bean
  @ConditionalOnMissingBean
  public PkAuthJwtIssuer pkAuthJwtIssuer(
      JwtConfig config,
      JwtKeyset keyset,
      ClockProvider clockProvider,
      AccessTokenStore accessTokenStore) {
    return new PkAuthJwtIssuer(config, keyset, clockProvider, accessTokenStore);
  }

  @Bean
  @ConditionalOnMissingBean
  public PkAuthJwtValidator pkAuthJwtValidator(
      JwtConfig config,
      JwtKeyset keyset,
      ClockProvider clockProvider,
      RevocationCheck revocationCheck,
      AccessTokenStore accessTokenStore) {
    return new PkAuthJwtValidator(config, keyset, clockProvider, revocationCheck, accessTokenStore);
  }

  // -- User deletion fan-out ------------------------------------------------------------------

  /** Listener: deletes every passkey credential owned by the user. */
  @Bean
  public UserDeletionListener pkAuthCredentialRepositoryDeletionListener(
      CredentialRepository repository) {
    return new CredentialRepositoryDeletionListener(repository);
  }

  /** Listener: deletes every backup code owned by the user — only when a repository is wired. */
  @Bean
  @ConditionalOnBean(BackupCodeRepository.class)
  public UserDeletionListener pkAuthBackupCodeRepositoryDeletionListener(
      BackupCodeRepository repository) {
    return new BackupCodeRepositoryDeletionListener(repository);
  }

  /** Listener: deletes every OTP row owned by the user — only when a repository is wired. */
  @Bean
  @ConditionalOnBean(OtpRepository.class)
  public UserDeletionListener pkAuthOtpRepositoryDeletionListener(OtpRepository repository) {
    return new OtpRepositoryDeletionListener(repository);
  }

  /**
   * Listener: deletes every stateful access-token row owned by the user (noop in stateless mode).
   */
  @Bean
  public UserDeletionListener pkAuthAccessTokenStoreDeletionListener(AccessTokenStore store) {
    return new AccessTokenStoreDeletionListener(store);
  }

  /**
   * Collects every {@link UserDeletionListener} bean and wires the fan-out service. Hosts can
   * register additional listeners by declaring their own {@code @Bean UserDeletionListener
   * myCustomListener(...)} — Spring auto-collects all beans of the interface type.
   */
  @Bean
  @ConditionalOnMissingBean
  public UserDeletionService pkAuthUserDeletionService(List<UserDeletionListener> listeners) {
    return new UserDeletionService(listeners);
  }

  // -- Refresh tokens (only active when a RefreshTokenRepository bean is present) -------------

  /**
   * Builds the {@link RefreshTokenConfig} from {@code pkauth.refresh.*} properties. Materialised
   * unconditionally so hosts can inject it for ad-hoc construction, but the bean only matters when
   * a {@link RefreshTokenRepository} is also bound.
   *
   * @since 1.1.0
   */
  @Bean
  @ConditionalOnMissingBean
  public RefreshTokenConfig pkAuthRefreshTokenConfig(PkAuthProperties props) {
    PkAuthProperties.Refresh refresh = props.refresh();
    return RefreshTokenConfig.from(
        refresh.defaultTtl(), refresh.ttlsByAudience(), refresh.cleanupRetention());
  }

  /** {@link RefreshTokenService} bean — only when a {@link RefreshTokenRepository} is wired. */
  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnBean(RefreshTokenRepository.class)
  public RefreshTokenService pkAuthRefreshTokenService(
      RefreshTokenRepository repository, RefreshTokenConfig config, ClockProvider clockProvider) {
    return new RefreshTokenService(repository, config, clockProvider);
  }

  /** Wires the user-deletion fan-out's refresh-token branch. */
  @Bean
  @ConditionalOnBean(RefreshTokenService.class)
  public UserDeletionListener pkAuthRefreshTokenServiceDeletionListener(
      RefreshTokenService service) {
    return new RefreshTokenServiceDeletionListener(service);
  }

  /** Framework-neutral handler that the controller delegates to. */
  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnBean(RefreshTokenService.class)
  public RefreshHandler pkAuthRefreshHandler(
      RefreshTokenService refreshService, PkAuthJwtIssuer issuer) {
    return new RefreshHandler(refreshService, issuer);
  }

  // -- Alt-flow services -----------------------------------------------------------------------

  /**
   * Logging email/SMS senders are dev-only: they write the full message body — which contains the
   * magic-link token or OTP code — to the application log. Gating them behind {@code
   * pkauth.dev-mode=true} prevents an accidental production deploy from silently leaking single-use
   * credentials to log aggregation systems. A host without a real {@code EmailSender} / {@code
   * SmsSender} bean (and without {@code dev-mode=true}) simply does not get the downstream {@code
   * MagicLinkService} / {@code OtpService} beans — those are {@link ConditionalOnBean} on their
   * sender/repository — so a passkey-only host boots cleanly. The admin service then reports those
   * flows as "not configured" rather than the application failing to start.
   */
  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "pkauth", name = "dev-mode", havingValue = "true")
  public EmailSender pkAuthEmailSender() {
    LOG.warn(
        "pkauth.dev-mode=true: using LoggingEmailSender — magic-link tokens will be written to"
            + " the application log. DO NOT use in production.");
    return new LoggingEmailSender();
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "pkauth", name = "dev-mode", havingValue = "true")
  public SmsSender pkAuthSmsSender() {
    LOG.warn(
        "pkauth.dev-mode=true: using LoggingSmsSender — OTP codes will be written to the"
            + " application log. DO NOT use in production.");
    return new LoggingSmsSender();
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnBean(BackupCodeRepository.class)
  public BackupCodeService pkAuthBackupCodeService(
      BackupCodeRepository repo, ClockProvider clockProvider) {
    return BackupCodeService.create(BackupCodeService.Dependencies.of(repo, clockProvider));
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnBean(EmailSender.class)
  public MagicLinkService pkAuthMagicLinkService(
      JwtConfig jwtConfig,
      JwtKeyset keyset,
      EmailSender emailSender,
      UserLookup userLookup,
      ClockProvider clockProvider,
      PkAuthProperties props) {
    // baseUrl for the magic link uses the configured RP origin's first entry. Demo apps that
    // serve at a different path override the service bean explicitly.
    String baseUrl = props.relyingParty().origins().iterator().next();
    // Dedicated magic-link issuer/validator scoped to MagicLinkService.DEFAULT_AUDIENCE so the
    // resource-server validator (application audience) rejects magic-link tokens as bearer tokens.
    return MagicLinkService.create(
        MagicLinkService.Dependencies.ofDedicatedAudience(
            keyset, jwtConfig.issuer(), emailSender, userLookup, clockProvider),
        baseUrl);
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnBean({OtpRepository.class, SmsSender.class})
  public OtpService pkAuthOtpService(
      OtpRepository repo,
      SmsSender smsSender,
      ClockProvider clockProvider,
      PkAuthProperties props) {
    byte[] pepper = OtpPepperResolver.resolve(() -> props.otp().pepper(), props::devMode);
    return OtpService.create(OtpService.Dependencies.of(repo, smsSender, clockProvider), pepper);
  }
}
