// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.config;

import com.codeheadsystems.pkauth.api.AttestationConveyance;
import com.codeheadsystems.pkauth.api.ResidentKeyRequirement;
import com.codeheadsystems.pkauth.api.UserVerificationRequirement;
import com.codeheadsystems.pkauth.config.CoseAlgorithm;
import com.codeheadsystems.pkauth.config.CounterRegressionPolicy;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Typed configuration for the pk-auth Spring Boot starter, bound to {@code pkauth.*} properties.
 *
 * <p>The starter follows Dropwizard's fail-fast policy: relying-party id, name, origins, JWT
 * issuer, audience, and signing secret are all required. Misconfiguration surfaces as a startup
 * failure with a remediation message rather than as silent dev-mode behaviour. Optional blocks
 * ({@code ceremony}, {@code otp}) default to empty/defaulted records.
 *
 * @param relyingParty relying-party identity used in WebAuthn ceremonies (required)
 * @param jwt JWT issuance / validation settings (required)
 * @param ceremony tunables for challenge TTL, user-verification, etc. (optional)
 * @param otp OTP service tunables (optional)
 * @param devMode {@code true} to enable in-memory testkit SPIs and logging email/SMS senders, plus
 *     auto-generation of a per-startup OTP pepper when {@code otp.pepper} is unset. Defaults to
 *     {@code false} — production deployments must supply real SPI beans, real senders, and a
 *     configured pepper. {@code @since 0.9.1}
 */
@ConfigurationProperties("pkauth")
public record PkAuthProperties(
    RelyingParty relyingParty,
    Jwt jwt,
    Ceremony ceremony,
    Otp otp,
    Refresh refresh,
    boolean devMode) {

  /**
   * Normalises the optional blocks ({@code ceremony}, {@code otp}, {@code refresh}) to their
   * defaults so callers don't have to null-check. Required blocks ({@code relyingParty}, {@code
   * jwt}) are left as the framework bound them — if absent, downstream wiring fails fast with a
   * clear message.
   */
  public PkAuthProperties {
    if (ceremony == null) {
      ceremony = Ceremony.defaults();
    }
    if (otp == null) {
      otp = Otp.defaults();
    }
    if (refresh == null) {
      refresh = Refresh.defaults();
    }
  }

  /**
   * Relying-party identity. All three fields are required (no defaults) — set {@code
   * pkauth.relying-party.id}, {@code .name}, and at least one {@code .origins[]} value.
   *
   * @param id WebAuthn relying-party id (typically the registrable domain, e.g. {@code
   *     example.com})
   * @param name human-readable label shown by the authenticator
   * @param origins allow-listed origins for ceremony validation; must contain at least one entry
   */
  public record RelyingParty(String id, String name, Set<String> origins) {}

  /**
   * JWT issuance and validation. {@code issuer}, {@code audience}, and {@code secret} are all
   * required — there is no random-key fallback. Only HS256 is configurable from properties;
   * adapters needing ES256 wire a {@code JwtKeyset} bean explicitly.
   *
   * @param issuer the {@code iss} claim (required)
   * @param audience the default {@code aud} claim, used when {@link
   *     com.codeheadsystems.pkauth.jwt.JwtClaims#audience()} is unset at issue time (required)
   * @param secret HS256 shared secret; must be ≥ 32 bytes when UTF-8 encoded (required)
   * @param defaultTtl access-token TTL applied to audiences not present in {@code ttlsByAudience};
   *     null falls back to {@link com.codeheadsystems.pkauth.jwt.JwtConfig#DEFAULT_TOKEN_TTL}
   * @param ttlsByAudience per-audience access-token TTL overrides (e.g. {@code web=PT15M,
   *     cli=PT1H}). Empty/null means every audience uses {@code defaultTtl}. Keys here also extend
   *     the validator's accepted-audience set via {@link
   *     com.codeheadsystems.pkauth.jwt.TokenTtlPolicy#knownAudiences()}.
   */
  public record Jwt(
      String issuer,
      String audience,
      String secret,
      @Nullable Duration defaultTtl,
      @Nullable Map<String, Duration> ttlsByAudience) {}

  /**
   * Ceremony tunables forwarded to {@code CeremonyConfig}. Every field is optional; any left unset
   * falls back to {@link com.codeheadsystems.pkauth.config.CeremonyConfig#defaults()} — notably
   * {@code userVerification} defaults to {@code REQUIRED} and {@code counterRegression} to {@code
   * REJECT}, matching the framework-neutral core defaults (and the Micronaut/Dropwizard adapters).
   * These are security-load-bearing; relaxing them (e.g. {@code user-verification: preferred} for
   * UV-less security keys) must be an explicit, deliberate host choice.
   *
   * @param challengeTtl how long an issued challenge remains valid (default 5 minutes)
   * @param userVerification WebAuthn UV requirement (default {@code REQUIRED})
   * @param residentKey discoverable-credential requirement (default {@code PREFERRED})
   * @param attestation attestation conveyance preference (default {@code NONE})
   * @param counterRegression signature-counter regression policy (default {@code REJECT})
   * @param offeredAlgorithms COSE algorithms advertised in create-options (default ES256, EdDSA,
   *     RS256); must be a subset of {@code acceptedAlgorithms}
   * @param acceptedAlgorithms COSE algorithms accepted on registration verify (default the
   *     historical union ES256, EdDSA, RS256, ES384, RS384); narrowing this can reject
   *     already-registered credentials, so change deliberately
   * @since 2.0.0
   */
  public record Ceremony(
      @Nullable Duration challengeTtl,
      @Nullable UserVerificationRequirement userVerification,
      @Nullable ResidentKeyRequirement residentKey,
      @Nullable AttestationConveyance attestation,
      @Nullable CounterRegressionPolicy counterRegression,
      @Nullable List<CoseAlgorithm> offeredAlgorithms,
      @Nullable List<CoseAlgorithm> acceptedAlgorithms) {

    public static Ceremony defaults() {
      return new Ceremony(Duration.ofMinutes(5), null, null, null, null, null, null);
    }
  }

  /**
   * OTP service tunables.
   *
   * @param pepper Base64-encoded server-side HMAC pepper for OTP code hashing. Decoded bytes must
   *     be at least 16 bytes (32+ recommended). Required in production. When unset, the starter
   *     will only auto-generate a per-startup random pepper if {@code pkauth.dev-mode=true}. A
   *     per-startup pepper invalidates outstanding OTPs across restarts and across cluster
   *     instances, which is unsafe in production.
   */
  public record Otp(@Nullable String pepper) {

    public static Otp defaults() {
      return new Otp(null);
    }
  }

  /**
   * Refresh-token service tunables. Only active when a {@code RefreshTokenRepository} bean is
   * present in the application context (the JDBI and DynamoDB persistence modules each provide
   * one).
   *
   * @param defaultTtl how long an issued refresh token lasts when its audience isn't listed in
   *     {@code ttlsByAudience}. Null defaults to {@code 14d}.
   * @param ttlsByAudience per-audience refresh TTL overrides (e.g. {@code web=PT336H,
   *     cli=PT2160H}). Empty/null means every audience uses {@code defaultTtl}.
   * @param cleanupRetention how long after a row is used or revoked to keep it for forensic
   *     visibility. Null defaults to {@code 30d}.
   * @param path HTTP path the {@code PkAuthRefreshController} mounts at; null defaults to {@code
   *     /auth/refresh}.
   * @since 1.1.0
   */
  public record Refresh(
      @Nullable Duration defaultTtl,
      @Nullable Map<String, Duration> ttlsByAudience,
      @Nullable Duration cleanupRetention,
      @Nullable String path) {

    public static Refresh defaults() {
      return new Refresh(null, null, null, null);
    }
  }
}
