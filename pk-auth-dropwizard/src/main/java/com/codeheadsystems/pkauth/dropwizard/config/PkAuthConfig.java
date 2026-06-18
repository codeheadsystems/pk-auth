// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.config;

import com.codeheadsystems.pkauth.config.CoseAlgorithm;
import com.codeheadsystems.pkauth.refresh.RefreshTokenConfig;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * Aggregated configuration for the Dropwizard adapter. Host applications carry this record on their
 * own {@code Configuration} class (see {@link
 * com.codeheadsystems.pkauth.dropwizard.HasPkAuthConfig}) and the bundle pulls it out at {@code
 * run()} time.
 *
 * <p>Defaults are intentionally not provided here — every field is required so misconfiguration
 * fails at start-up rather than silently using a dev-only value in production.
 *
 * <p>The alt-flow blocks ({@link Otp}, {@link MagicLink}, {@link BackupCode}) are optional at the
 * record level so a host that only ships passkey ceremony endpoints does not have to provide them.
 * When the host registers the bundle with admin / alt-flow auto-wiring enabled the bundle requires
 * the relevant blocks to be present and fails fast at start-up otherwise.
 *
 * @param relyingParty RP identity (id, name, origins) used for WebAuthn ceremonies.
 * @param jwt JWT issuer, audience, and signing-key material.
 * @param ceremony Ceremony policy knobs (challenge TTL, etc.).
 * @param otp OTP tunables; required when alt-flow auto-wiring is enabled, else null.
 * @param magicLink Magic-link tunables; required when alt-flow auto-wiring is enabled, else null.
 * @param backupCode Backup-code tunables; required when alt-flow auto-wiring is enabled, else null.
 * @since 0.9.1
 */
public record PkAuthConfig(
    RelyingParty relyingParty,
    Jwt jwt,
    Ceremony ceremony,
    @Nullable Otp otp,
    @Nullable MagicLink magicLink,
    @Nullable BackupCode backupCode,
    @Nullable Refresh refresh) {

  public PkAuthConfig {
    Objects.requireNonNull(relyingParty, "relyingParty");
    Objects.requireNonNull(jwt, "jwt");
    Objects.requireNonNull(ceremony, "ceremony");
  }

  /**
   * Backwards-compatible four-arg constructor for hosts that do not configure alt-flow services.
   * Equivalent to {@code new PkAuthConfig(relyingParty, jwt, ceremony, null, null, null, null)}.
   *
   * @since 0.9.1
   */
  public PkAuthConfig(RelyingParty relyingParty, Jwt jwt, Ceremony ceremony) {
    this(relyingParty, jwt, ceremony, null, null, null, null);
  }

  /**
   * Six-arg constructor preserved for callers that pre-date the refresh-token block. Equivalent to
   * passing {@code null} for {@code refresh}.
   *
   * @since 0.9.1
   */
  public PkAuthConfig(
      RelyingParty relyingParty,
      Jwt jwt,
      Ceremony ceremony,
      @Nullable Otp otp,
      @Nullable MagicLink magicLink,
      @Nullable BackupCode backupCode) {
    this(relyingParty, jwt, ceremony, otp, magicLink, backupCode, null);
  }

  /**
   * Relying-party block. Mirrors {@link com.codeheadsystems.pkauth.config.RelyingPartyConfig} but
   * lives in the adapter package so YAML can bind to it without dragging Jackson onto core.
   *
   * @param id WebAuthn RP id (e.g. {@code "example.com"}).
   * @param name Human-readable RP name shown to the user during ceremonies.
   * @param origins Allowed client-reported origins.
   */
  public record RelyingParty(String id, String name, Set<String> origins) {
    public RelyingParty {
      Objects.requireNonNull(id, "id");
      Objects.requireNonNull(name, "name");
      Objects.requireNonNull(origins, "origins");
      if (origins.isEmpty()) {
        throw new IllegalArgumentException("at least one origin required");
      }
      origins = Set.copyOf(new LinkedHashSet<>(origins));
    }
  }

  /**
   * JWT block. Both {@code secret} (HS256) and {@code audience} are required so the bundle can mint
   * tokens at the end of a successful authentication ceremony.
   *
   * @param issuer iss claim value.
   * @param audience the default {@code aud} claim used when {@link
   *     com.codeheadsystems.pkauth.jwt.JwtClaims#audience()} is unset at issue time.
   * @param secret Raw HMAC secret bytes; must be at least 32 bytes for HS256.
   * @param defaultTtl access-token TTL applied to audiences without an override; null defers to
   *     {@link com.codeheadsystems.pkauth.jwt.JwtConfig#DEFAULT_TOKEN_TTL}.
   * @param ttlsByAudience per-audience access-token TTL overrides (e.g. {@code web: PT15M, cli:
   *     PT1H}). The keys here also extend the validator's accepted-audience set via {@link
   *     com.codeheadsystems.pkauth.jwt.TokenTtlPolicy#knownAudiences()}.
   */
  public record Jwt(
      String issuer,
      String audience,
      byte[] secret,
      @Nullable Duration defaultTtl,
      @Nullable Map<String, Duration> ttlsByAudience) {
    public Jwt {
      Objects.requireNonNull(issuer, "issuer");
      Objects.requireNonNull(audience, "audience");
      Objects.requireNonNull(secret, "secret");
      if (secret.length < 32) {
        throw new IllegalArgumentException(
            "HS256 secret must be >= 32 bytes (got " + secret.length + ")");
      }
      // Defensive copy to keep callers from mutating the byte[] under us.
      secret = secret.clone();
      if (ttlsByAudience != null) {
        ttlsByAudience = Map.copyOf(new LinkedHashMap<>(ttlsByAudience));
      }
    }

    /**
     * Four-arg constructor for hosts that do not configure per-audience overrides. Equivalent to
     * passing {@code null} for {@code ttlsByAudience}.
     */
    public Jwt(String issuer, String audience, byte[] secret, @Nullable Duration defaultTtl) {
      this(issuer, audience, secret, defaultTtl, null);
    }

    /** Returns a fresh defensive copy of the underlying secret. */
    @Override
    public byte[] secret() {
      return secret.clone();
    }
  }

  /**
   * Ceremony policy knobs. Optional; nulls fall back to {@link
   * com.codeheadsystems.pkauth.config.CeremonyConfig#defaults()}.
   *
   * @param challengeTtl Override for challenge TTL; null = use the brief's 5-minute default.
   * @param offeredAlgorithms COSE algorithms advertised in create-options; null = core default
   *     (ES256, EdDSA, RS256). Must be a subset of {@code acceptedAlgorithms}.
   * @param acceptedAlgorithms COSE algorithms accepted on verify; null = core default union (ES256,
   *     EdDSA, RS256, ES384, RS384). Narrowing can reject already-registered credentials.
   */
  public record Ceremony(
      @Nullable Duration challengeTtl,
      @Nullable List<CoseAlgorithm> offeredAlgorithms,
      @Nullable List<CoseAlgorithm> acceptedAlgorithms) {
    public Ceremony() {
      this(null, null, null);
    }

    /** Back-compat convenience for the TTL-only construction used before crypto-agility config. */
    public Ceremony(@Nullable Duration challengeTtl) {
      this(challengeTtl, null, null);
    }
  }

  /**
   * OTP service tunables. Mirrors Spring's {@code pkauth.otp} and Micronaut's {@code pkauth.otp}.
   *
   * <p>{@code pepper} is the server-side HMAC pepper for OTP-code hashing — required in production,
   * no default. Decoded bytes must be at least 16 (32+ recommended). A captured DB dump without
   * this value cannot brute-force outstanding codes.
   *
   * @param pepper raw pepper bytes; ≥ 16 bytes required.
   * @since 0.9.1
   */
  public record Otp(byte[] pepper) {
    public Otp {
      Objects.requireNonNull(pepper, "pepper");
      if (pepper.length < 16) {
        throw new IllegalArgumentException(
            "OTP pepper must be >= 16 bytes (got " + pepper.length + ")");
      }
      pepper = pepper.clone();
    }

    /** Returns a fresh defensive copy of the underlying pepper. */
    @Override
    public byte[] pepper() {
      return pepper.clone();
    }
  }

  /**
   * Magic-link service tunables. Mirrors Spring's {@code pkauth.magicLink} (which derives baseUrl
   * from the first RP origin) and Micronaut's hard-coded {@code http://localhost:8080/auth/magic} —
   * the Dropwizard adapter requires hosts to spell baseUrl out so production deploys cannot fall
   * through to a development default.
   *
   * @param baseUrl the URL prefix the magic-link will be assembled against — required, no default.
   * @since 0.9.1
   */
  public record MagicLink(String baseUrl) {
    public MagicLink {
      Objects.requireNonNull(baseUrl, "baseUrl");
      if (baseUrl.isBlank()) {
        throw new IllegalArgumentException("magicLink.baseUrl must be non-blank");
      }
    }
  }

  /**
   * Backup-code service tunables. The current {@code BackupCodeService} surface has no required
   * configuration beyond its SPI collaborators, so this block exists purely as a future seam
   * (matching Spring / Micronaut's symmetric block shape). Pass an empty record if you want the
   * service auto-wired with library defaults.
   *
   * @since 0.9.1
   */
  public record BackupCode() {}

  /**
   * Refresh-token tunables. Only consulted when the host wires a {@link
   * com.codeheadsystems.pkauth.refresh.spi.RefreshTokenRepository} via {@link
   * com.codeheadsystems.pkauth.dropwizard.dagger.PersistenceBindings.Builder#refreshTokenRepository}.
   *
   * @param defaultTtl how long a refresh token lasts when its audience isn't in {@code
   *     ttlsByAudience}; null defaults to {@link RefreshTokenConfig#DEFAULT_REFRESH_TTL}.
   * @param ttlsByAudience per-audience refresh TTL overrides.
   * @param cleanupRetention forensic-retention window; null defaults to {@link
   *     RefreshTokenConfig#DEFAULT_CLEANUP_RETENTION}.
   * @since 1.1.0
   */
  public record Refresh(
      @Nullable Duration defaultTtl,
      @Nullable Map<String, Duration> ttlsByAudience,
      @Nullable Duration cleanupRetention) {

    /** Default block: every value null (effective defaults from {@link RefreshTokenConfig}). */
    public Refresh() {
      this(null, null, null);
    }

    /** Builds a {@link RefreshTokenConfig} from this block. */
    public RefreshTokenConfig toRefreshTokenConfig() {
      return RefreshTokenConfig.from(defaultTtl, ttlsByAudience, cleanupRetention);
    }
  }
}
