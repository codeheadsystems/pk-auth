// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import java.time.Duration;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * Configuration for pk-auth's JWT issuance and validation.
 *
 * <p>The {@code defaultAudience} is the audience the issuer uses when {@link JwtClaims#audience()}
 * is null on a call to {@link PkAuthJwtIssuer#issue(JwtClaims)}, and is always accepted by the
 * validator. Additional accepted audiences come from {@link TokenTtlPolicy#knownAudiences()} — see
 * {@link #allowedAudiences()} for the resolved set.
 *
 * <p><strong>Access-token TTL is your revocation window in stateless mode.</strong> With the
 * default {@link AccessTokenStore#noop() no-op access-token store}, pk-auth issues stateless JWTs
 * that cannot be invalidated before their {@code exp} — a logout or user-disable only stops
 * <em>new</em> tokens, while already-issued access tokens stay valid until they expire. The access
 * TTL ({@link #DEFAULT_TOKEN_TTL} = 1 hour by default, or per-audience via {@link TokenTtlPolicy})
 * is therefore the worst-case window an attacker keeps access after credentials are pulled; keep it
 * short (minutes-to-an-hour) and pair it with rotating refresh tokens for long sessions. Hosts that
 * need <em>immediate</em> revocation must bind a real {@link AccessTokenStore} (stateful mode); see
 * ADR 0015.
 *
 * @param issuer the {@code iss} claim value
 * @param defaultAudience the audience used when {@link JwtClaims#audience()} is absent at issue
 *     time; always part of {@link #allowedAudiences()}
 * @param ttlPolicy per-audience access-token TTL dispatch
 * @param notBeforeSkew the {@code nbf} claim is set to {@code iat - notBeforeSkew} (small negative
 *     skew helps clients with slightly fast clocks accept tokens immediately)
 * @param clockSkew leniency window applied to {@code exp} and {@code nbf} during validation
 */
public record JwtConfig(
    String issuer,
    String defaultAudience,
    TokenTtlPolicy ttlPolicy,
    Duration notBeforeSkew,
    Duration clockSkew) {

  /** Default token TTL: 1 hour. */
  public static final Duration DEFAULT_TOKEN_TTL = Duration.ofHours(1);

  /** Default not-before skew applied at issuance: 30 seconds back. */
  public static final Duration DEFAULT_NBF_SKEW = Duration.ofSeconds(30);

  /** Default validation tolerance for clock skew: 30 seconds. */
  public static final Duration DEFAULT_CLOCK_SKEW = Duration.ofSeconds(30);

  public JwtConfig {
    Objects.requireNonNull(issuer, "issuer");
    if (issuer.isBlank()) {
      throw new IllegalArgumentException("issuer must be non-blank");
    }
    Objects.requireNonNull(defaultAudience, "defaultAudience");
    if (defaultAudience.isBlank()) {
      throw new IllegalArgumentException("defaultAudience must be non-blank");
    }
    Objects.requireNonNull(ttlPolicy, "ttlPolicy");
    Objects.requireNonNull(notBeforeSkew, "notBeforeSkew");
    if (notBeforeSkew.isNegative()) {
      throw new IllegalArgumentException("notBeforeSkew must be non-negative");
    }
    Objects.requireNonNull(clockSkew, "clockSkew");
    if (clockSkew.isNegative()) {
      throw new IllegalArgumentException("clockSkew must be non-negative");
    }
  }

  /**
   * Returns the audiences the validator accepts for an issued token: the {@link #defaultAudience()}
   * union {@link TokenTtlPolicy#knownAudiences()}. Always contains {@link #defaultAudience()}.
   */
  public Set<String> allowedAudiences() {
    Set<String> known = ttlPolicy.knownAudiences();
    if (known.isEmpty()) {
      return Set.of(defaultAudience);
    }
    Set<String> all = new HashSet<>(known);
    all.add(defaultAudience);
    return Set.copyOf(all);
  }

  /**
   * Convenience constructor with the documented defaults — a single-TTL policy and the standard
   * skew values.
   */
  public static JwtConfig defaults(String issuer, String audience) {
    return new JwtConfig(
        issuer,
        audience,
        TokenTtlPolicy.single(DEFAULT_TOKEN_TTL),
        DEFAULT_NBF_SKEW,
        DEFAULT_CLOCK_SKEW);
  }

  /**
   * Builds a {@link JwtConfig} from host configuration with the documented skew defaults ({@link
   * #DEFAULT_NBF_SKEW} / {@link #DEFAULT_CLOCK_SKEW}). A {@code null} {@code defaultTtl} falls back
   * to {@link #DEFAULT_TOKEN_TTL}; {@code ttlsByAudience} that is {@code null} or empty yields a
   * single-TTL policy, otherwise a per-audience policy (see {@link TokenTtlPolicy#from}).
   *
   * <p>This is the host-config-to-domain-config translation every framework adapter performs.
   * Centralizing it ensures all adapters issue tokens with identical skew windows — a divergence
   * here would be a silent, security-relevant inconsistency.
   *
   * @param issuer the {@code iss} claim value.
   * @param audience the default audience.
   * @param defaultTtl the access-token TTL, or {@code null} for {@link #DEFAULT_TOKEN_TTL}.
   * @param ttlsByAudience per-audience TTL overrides, or {@code null}/empty for a uniform TTL.
   * @return the assembled config.
   * @since 2.0.0
   */
  public static JwtConfig from(
      String issuer,
      String audience,
      @Nullable Duration defaultTtl,
      @Nullable Map<String, Duration> ttlsByAudience) {
    Duration ttl = defaultTtl == null ? DEFAULT_TOKEN_TTL : defaultTtl;
    return new JwtConfig(
        issuer,
        audience,
        TokenTtlPolicy.from(ttl, ttlsByAudience),
        DEFAULT_NBF_SKEW,
        DEFAULT_CLOCK_SKEW);
  }
}
