// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh;

import com.codeheadsystems.pkauth.jwt.TokenTtlPolicy;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * Per-audience TTL lookup used by {@link RefreshTokenService} when issuing refresh tokens.
 * Parallels {@link TokenTtlPolicy} on the access-token side; different client kinds typically want
 * very different refresh lifetimes (web=14d, cli=90d, …).
 *
 * <p>Implementations are expected to be cheap and side-effect-free. Built-in factories cover the
 * common cases:
 *
 * <ul>
 *   <li>{@link #fixed(Duration, Map)}: static map of audience → TTL with a default fallback
 *   <li>{@link #single(Duration)}: same TTL for every audience
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
   * audience set elsewhere"; analogous to {@link TokenTtlPolicy#knownAudiences()}.
   */
  default Set<String> knownAudiences() {
    return Set.of();
  }

  /**
   * Builds a policy from optional host configuration: {@link #single(Duration)} when {@code
   * overrides} is {@code null} or empty, otherwise {@link #fixed(Duration, Map)}. This is the
   * single-vs-fixed dispatch every adapter performs; centralising it keeps the JDBI/DynamoDB-backed
   * hosts identical on the refresh-TTL decision.
   *
   * @param defaultTtl the fallback TTL for any audience not in {@code overrides}.
   * @param overrides per-audience TTL overrides, or {@code null}/empty for a uniform TTL.
   * @return the resolved policy.
   * @since 2.0.0
   */
  static RefreshTtlPolicy from(Duration defaultTtl, @Nullable Map<String, Duration> overrides) {
    return new TokenTtlPolicyAdapter(TokenTtlPolicy.from(defaultTtl, overrides));
  }

  /**
   * Returns a policy dispatching by audience with a default-TTL fallback. Validation and dispatch
   * are shared with {@link TokenTtlPolicy#fixed(Duration, Map)}.
   */
  static RefreshTtlPolicy fixed(Duration defaultTtl, Map<String, Duration> overrides) {
    return new TokenTtlPolicyAdapter(TokenTtlPolicy.fixed(defaultTtl, overrides));
  }

  /**
   * Returns a policy that uses the same TTL for every audience. Validation is shared with {@link
   * TokenTtlPolicy#single(Duration)}.
   */
  static RefreshTtlPolicy single(Duration ttl) {
    return new TokenTtlPolicyAdapter(TokenTtlPolicy.single(ttl));
  }
}
