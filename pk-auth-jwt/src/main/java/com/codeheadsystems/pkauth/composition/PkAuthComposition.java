// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.composition;

import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationServices;
import com.codeheadsystems.pkauth.config.CeremonyConfig;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.jwt.CeremonyOrchestrator;
import com.codeheadsystems.pkauth.jwt.JwtConfig;
import com.codeheadsystems.pkauth.jwt.JwtKeyset;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.spi.CeremonyRateLimiter;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;

/**
 * Framework-neutral wiring recipes for the three blocks every pk-auth adapter has to build: {@link
 * PasskeyAuthenticationService}, the {@link PkAuthJwtIssuer} / {@link PkAuthJwtValidator} pair, and
 * the {@link CeremonyOrchestrator}.
 *
 * <p>Adapter modules (Spring auto-configuration, Dropwizard Dagger module, Micronaut factory) call
 * these static factories from their per-framework providers so the construction graph is named in
 * one place. The CeremonyConfig / JwtConfig merge-with-defaults policy is not encoded here: each
 * adapter binds those from its own configuration shape and is free to apply its own conservative or
 * permissive defaults. Only the downstream assembly of a service from an existing {@code
 * CeremonyConfig} is shared.
 *
 * @since 0.9.1
 */
public final class PkAuthComposition {

  private PkAuthComposition() {}

  /**
   * Wires the canonical {@link PasskeyAuthenticationService} via {@link
   * PasskeyAuthenticationServices#builder()}. Adapter providers call this so the seven-argument
   * builder lives in one place rather than three.
   *
   * @since 0.9.1
   */
  public static PasskeyAuthenticationService passkeyAuthenticationService(
      CredentialRepository credentialRepository,
      UserLookup userLookup,
      ChallengeStore challengeStore,
      ClockProvider clockProvider,
      RelyingPartyConfig relyingPartyConfig,
      CeremonyConfig ceremonyConfig,
      CeremonyRateLimiter ceremonyRateLimiter) {
    return PasskeyAuthenticationServices.builder()
        .credentialRepository(credentialRepository)
        .userLookup(userLookup)
        .challengeStore(challengeStore)
        .clockProvider(clockProvider)
        .relyingPartyConfig(relyingPartyConfig)
        .ceremonyConfig(ceremonyConfig)
        .ceremonyRateLimiter(ceremonyRateLimiter)
        .build();
  }

  /** Wires the JWT issuer + validator from a shared config / keyset / clock. */
  public record JwtPair(PkAuthJwtIssuer issuer, PkAuthJwtValidator validator) {}

  /**
   * Wires the {@link PkAuthJwtIssuer} / {@link PkAuthJwtValidator} pair around the same {@link
   * JwtConfig}, {@link JwtKeyset}, and {@link ClockProvider}. Adapters that prefer to register each
   * as its own bean can call {@link #passkeyAuthenticationService} and then construct issuer /
   * validator directly; both shapes are supported.
   *
   * @since 0.9.1
   */
  public static JwtPair jwtPair(JwtConfig config, JwtKeyset keyset, ClockProvider clockProvider) {
    return new JwtPair(
        new PkAuthJwtIssuer(config, keyset, clockProvider),
        new PkAuthJwtValidator(config, keyset, clockProvider));
  }

  /**
   * Wires the ceremony orchestrator.
   *
   * @since 0.9.1
   */
  public static CeremonyOrchestrator ceremonyOrchestrator(
      PasskeyAuthenticationService service,
      PkAuthJwtIssuer issuer,
      CredentialRepository credentialRepository) {
    return new CeremonyOrchestrator(service, issuer, credentialRepository);
  }
}
