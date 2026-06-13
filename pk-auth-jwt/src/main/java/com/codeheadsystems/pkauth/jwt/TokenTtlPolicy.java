// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * Per-audience TTL lookup used by {@link PkAuthJwtIssuer} when minting access tokens. Hosts that
 * issue tokens for distinct client audiences (e.g. {@code web}, {@code ios}, {@code cli}) typically
 * want different access-token lifetimes per audience; the policy is the dispatch seam.
 *
 * <p>Implementations are expected to be cheap and side-effect-free: {@link #accessTtl(String)} is
 * called once per {@link PkAuthJwtIssuer#issue(JwtClaims)} invocation.
 *
 * <p>{@link #knownAudiences()} declares which audiences this policy is configured for. The
 * validator (and adapters that want to enumerate accepted audiences for documentation or OpenAPI
 * surfaces) reads this set. Returning an empty set is the conservative default — the validator
 * falls back to accepting only {@link JwtConfig#defaultAudience()} in that case. The built-in
 * {@link #fixed(Duration, Map)} factory wires this automatically from the override map's keys.
 */
public interface TokenTtlPolicy {

  /**
   * Returns the access-token TTL for the given audience. Must always return a positive duration.
   */
  Duration accessTtl(String audience);

  /**
   * Audiences this policy explicitly knows about. The default returns an empty set; implementations
   * with a finite, enumerable audience set (e.g. {@link #fixed(Duration, Map)}) override this so
   * the validator can accept tokens for any of them. Returning empty means "validator accepts only
   * the issuer's default audience".
   */
  default Set<String> knownAudiences() {
    return Set.of();
  }

  /**
   * Returns a policy that dispatches to {@code overrides} by audience, falling back to {@code
   * defaultTtl} for any audience not present in the map.
   *
   * <p>{@link #knownAudiences()} on the returned policy is the union of {@code overrides.keySet()}.
   * The default TTL audience is not implied — a token issued for an audience that is neither in the
   * override map nor equal to {@link JwtConfig#defaultAudience()} will use {@code defaultTtl} but
   * will not be accepted by the validator unless the host declares the audience another way.
   */
  static TokenTtlPolicy fixed(Duration defaultTtl, Map<String, Duration> overrides) {
    Objects.requireNonNull(defaultTtl, "defaultTtl");
    Objects.requireNonNull(overrides, "overrides");
    if (defaultTtl.isZero() || defaultTtl.isNegative()) {
      throw new IllegalArgumentException("defaultTtl must be positive");
    }
    Map<String, Duration> copy = new LinkedHashMap<>();
    for (Map.Entry<String, Duration> e : overrides.entrySet()) {
      Objects.requireNonNull(e.getKey(), "override audience");
      Objects.requireNonNull(e.getValue(), "override ttl for " + e.getKey());
      if (e.getValue().isZero() || e.getValue().isNegative()) {
        throw new IllegalArgumentException(
            "ttl for audience '" + e.getKey() + "' must be positive");
      }
      copy.put(e.getKey(), e.getValue());
    }
    Map<String, Duration> frozen = Map.copyOf(copy);
    Set<String> audiences = Set.copyOf(frozen.keySet());
    return new TokenTtlPolicy() {
      @Override
      public Duration accessTtl(String audience) {
        Duration explicit = frozen.get(audience);
        return explicit != null ? explicit : defaultTtl;
      }

      @Override
      public Set<String> knownAudiences() {
        return audiences;
      }

      @Override
      public String toString() {
        return "TokenTtlPolicy.fixed(default=" + defaultTtl + ", overrides=" + frozen + ")";
      }
    };
  }

  /**
   * Builds a policy from optional host configuration: {@link #single(Duration)} when {@code
   * overrides} is {@code null} or empty, otherwise {@link #fixed(Duration, Map)}. This is the
   * single-vs-fixed dispatch every adapter performs when translating its per-audience TTL config;
   * centralizing it keeps that decision identical across adapters.
   *
   * @param defaultTtl the fallback TTL for any audience not in {@code overrides}.
   * @param overrides per-audience TTL overrides, or {@code null}/empty for a uniform TTL.
   * @return the resolved policy.
   * @since 2.0.0
   */
  static TokenTtlPolicy from(Duration defaultTtl, @Nullable Map<String, Duration> overrides) {
    return overrides == null || overrides.isEmpty()
        ? single(defaultTtl)
        : fixed(defaultTtl, overrides);
  }

  /** Returns a policy that uses the same TTL for every audience. */
  static TokenTtlPolicy single(Duration ttl) {
    Objects.requireNonNull(ttl, "ttl");
    if (ttl.isZero() || ttl.isNegative()) {
      throw new IllegalArgumentException("ttl must be positive");
    }
    return new TokenTtlPolicy() {
      @Override
      public Duration accessTtl(String audience) {
        return ttl;
      }

      @Override
      public String toString() {
        return "TokenTtlPolicy.single(" + ttl + ")";
      }
    };
  }
}
