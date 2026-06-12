// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.ceremony;

import com.codeheadsystems.pkauth.api.AttestationConveyance;
import com.codeheadsystems.pkauth.config.CeremonyConfig;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.internal.ChallengeGenerator;
import com.codeheadsystems.pkauth.internal.DefaultPasskeyAuthenticationService;
import com.codeheadsystems.pkauth.metrics.Metrics;
import com.codeheadsystems.pkauth.spi.AttestationTrustPolicy;
import com.codeheadsystems.pkauth.spi.CeremonyRateLimiter;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.OriginValidator;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.ObjectConverter;
import java.security.SecureRandom;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Public entry point for constructing a {@link PasskeyAuthenticationService}. Hides the internal
 * implementation class while still letting callers wire each SPI explicitly.
 *
 * @since 0.9.0
 */
public final class PasskeyAuthenticationServices {

  private PasskeyAuthenticationServices() {}

  /** Builder so adapter modules can wire only the SPIs they actually customize. */
  public static Builder builder() {
    return new Builder();
  }

  /** Builder for {@link PasskeyAuthenticationService}. All fields except metrics are required. */
  public static final class Builder {
    private @Nullable WebAuthnManager webAuthnManager;
    private @Nullable ObjectConverter objectConverter;
    private @Nullable CredentialRepository credentialRepository;
    private @Nullable UserLookup userLookup;
    private @Nullable ChallengeStore challengeStore;
    private ClockProvider clockProvider = ClockProvider.system();
    private @Nullable OriginValidator originValidator;
    private AttestationTrustPolicy attestationTrustPolicy = AttestationTrustPolicy.none();
    private @Nullable RelyingPartyConfig rpConfig;
    private CeremonyConfig ceremonyConfig = CeremonyConfig.defaults();
    private SecureRandom secureRandom = new SecureRandom();
    private Metrics metrics = Metrics.noop();
    private @Nullable CeremonyRateLimiter ceremonyRateLimiter;

    private Builder() {}

    public Builder webAuthnManager(WebAuthnManager webAuthnManager) {
      this.webAuthnManager = webAuthnManager;
      return this;
    }

    public Builder objectConverter(ObjectConverter objectConverter) {
      this.objectConverter = objectConverter;
      return this;
    }

    public Builder credentialRepository(CredentialRepository credentialRepository) {
      this.credentialRepository = credentialRepository;
      return this;
    }

    public Builder userLookup(UserLookup userLookup) {
      this.userLookup = userLookup;
      return this;
    }

    public Builder challengeStore(ChallengeStore challengeStore) {
      this.challengeStore = challengeStore;
      return this;
    }

    public Builder clockProvider(ClockProvider clockProvider) {
      this.clockProvider = clockProvider;
      return this;
    }

    public Builder originValidator(OriginValidator originValidator) {
      this.originValidator = originValidator;
      return this;
    }

    public Builder attestationTrustPolicy(AttestationTrustPolicy attestationTrustPolicy) {
      this.attestationTrustPolicy = attestationTrustPolicy;
      return this;
    }

    public Builder relyingPartyConfig(RelyingPartyConfig relyingPartyConfig) {
      this.rpConfig = relyingPartyConfig;
      return this;
    }

    public Builder ceremonyConfig(CeremonyConfig ceremonyConfig) {
      this.ceremonyConfig = ceremonyConfig;
      return this;
    }

    /** Override the {@link SecureRandom} used for challenge generation (test seam). */
    public Builder secureRandom(SecureRandom secureRandom) {
      this.secureRandom = secureRandom;
      return this;
    }

    public Builder metrics(Metrics metrics) {
      this.metrics = metrics;
      return this;
    }

    /**
     * Override the {@link CeremonyRateLimiter} consulted on every ceremony entrypoint. When unset,
     * the builder wires an {@link InMemoryCeremonyRateLimiter} with the default per-IP /
     * per-username allowances. Multi-replica deployments MUST supply a shared (Redis / DB-backed)
     * implementation here; the in-memory default tracks counters per-process and per-replica
     * counters multiply by the cluster size.
     *
     * @param ceremonyRateLimiter a non-null limiter implementation
     * @return this builder
     * @since 0.9.1
     */
    public Builder ceremonyRateLimiter(CeremonyRateLimiter ceremonyRateLimiter) {
      this.ceremonyRateLimiter = Objects.requireNonNull(ceremonyRateLimiter, "ceremonyRateLimiter");
      return this;
    }

    public PasskeyAuthenticationService build() {
      ObjectConverter oc = objectConverter == null ? new ObjectConverter() : objectConverter;
      // The default non-strict WebAuthnManager skips attestation-statement signature
      // verification. That's fine when conveyance is NONE (the authenticator returns a "none"
      // attestation statement with no signature anyway), but it would silently mislead an
      // operator who has configured DIRECT / INDIRECT / ENTERPRISE conveyance expecting their
      // AttestationTrustPolicy to act on a verified statement. Force the operator to wire a
      // strict manager explicitly via Builder#webAuthnManager(...) in that case.
      if (webAuthnManager == null
          && ceremonyConfig.attestationConveyance() != AttestationConveyance.NONE) {
        throw new IllegalStateException(
            "ceremonyConfig.attestationConveyance="
                + ceremonyConfig.attestationConveyance()
                + " requires an explicitly-wired WebAuthnManager (strict, with attestation"
                + " statement verifiers). Call Builder#webAuthnManager(...) with a manager built"
                + " via WebAuthnManager.createWebAuthnManager(verifiers, ...) before build(), or"
                + " set ceremonyConfig.attestationConveyance=NONE if you do not need attestation"
                + " signatures verified.");
      }
      WebAuthnManager mgr =
          webAuthnManager == null
              ? WebAuthnManager.createNonStrictWebAuthnManager(oc)
              : webAuthnManager;
      RelyingPartyConfig rp = Objects.requireNonNull(rpConfig, "relyingPartyConfig must be set");
      OriginValidator origins =
          originValidator == null ? OriginValidator.strict(rp) : originValidator;
      CeremonyRateLimiter limiter =
          ceremonyRateLimiter == null ? new InMemoryCeremonyRateLimiter() : ceremonyRateLimiter;
      return new DefaultPasskeyAuthenticationService(
          mgr,
          oc,
          Objects.requireNonNull(credentialRepository, "credentialRepository must be set"),
          Objects.requireNonNull(userLookup, "userLookup must be set"),
          Objects.requireNonNull(challengeStore, "challengeStore must be set"),
          clockProvider,
          origins,
          attestationTrustPolicy,
          rp,
          ceremonyConfig,
          new ChallengeGenerator(secureRandom),
          metrics,
          limiter);
    }
  }
}
