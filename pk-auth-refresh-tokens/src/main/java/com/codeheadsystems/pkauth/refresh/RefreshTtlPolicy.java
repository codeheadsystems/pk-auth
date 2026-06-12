// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * Per-audience TTL lookup used by {@link RefreshTokenService} when issuing refresh tokens.
 * Parallels {@link com.codeheadsystems.pkauth.jwt.TokenTtlPolicy} on the access-token side —
 * different client kinds typically want very different refresh lifetimes (web=14d, cli=90d, …).
 *
 * <p>Implementations are expected to be cheap and side-effect-free. Built-in factories cover the
 * common cases:
 *
 * <ul>
 *   <li>{@link #fixed(Duration, Map)} — static map of audience → TTL with a default fallback
 *   <li>{@link #single(Duration)} — same TTL for every audience
 * </ul>
 *
 * @since 1.1.0
 */
public interface RefreshTtlPolicy {

  /**
   * Returns the refresh-token TTL for the given audience. Must always return a positive duration.
   */
  Duration refreshTtl(String audience);

  /**
   * Audiences this policy explicitly knows about. Empty means "validator falls back to the default
   * audience set elsewhere" — analogous to {@link
   * com.codeheadsystems.pkauth.jwt.TokenTtlPolicy#knownAudiences()}.
   */
  default Set<String> knownAudiences() {
    return Set.of();
  }

  /**
   * Builds a policy from optional host configuration: {@link #single(Duration)} when {@code
   * overrides} is {@code null} or empty, otherwise {@link #fixed(Duration, Map)}. This is the
   * single-vs-fixed dispatch every adapter performs; centralizing it keeps the JDBI/DynamoDB-backed
   * hosts identical on the refresh-TTL decision.
   *
   * @param defaultTtl the fallback TTL for any audience not in {@code overrides}.
   * @param overrides per-audience TTL overrides, or {@code null}/empty for a uniform TTL.
   * @return the resolved policy.
   * @since 1.3.1
   */
  static RefreshTtlPolicy from(Duration defaultTtl, @Nullable Map<String, Duration> overrides) {
    return overrides == null || overrides.isEmpty()
        ? single(defaultTtl)
        : fixed(defaultTtl, overrides);
  }

  /** Returns a policy dispatching by audience with a default-TTL fallback. */
  static RefreshTtlPolicy fixed(Duration defaultTtl, Map<String, Duration> overrides) {
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
    return new RefreshTtlPolicy() {
      @Override
      public Duration refreshTtl(String audience) {
        Duration explicit = frozen.get(audience);
        return explicit != null ? explicit : defaultTtl;
      }

      @Override
      public Set<String> knownAudiences() {
        return audiences;
      }

      @Override
      public String toString() {
        return "RefreshTtlPolicy.fixed(default=" + defaultTtl + ", overrides=" + frozen + ")";
      }
    };
  }

  /** Returns a policy that uses the same TTL for every audience. */
  static RefreshTtlPolicy single(Duration ttl) {
    Objects.requireNonNull(ttl, "ttl");
    if (ttl.isZero() || ttl.isNegative()) {
      throw new IllegalArgumentException("ttl must be positive");
    }
    return new RefreshTtlPolicy() {
      @Override
      public Duration refreshTtl(String audience) {
        return ttl;
      }

      @Override
      public String toString() {
        return "RefreshTtlPolicy.single(" + ttl + ")";
      }
    };
  }
}
