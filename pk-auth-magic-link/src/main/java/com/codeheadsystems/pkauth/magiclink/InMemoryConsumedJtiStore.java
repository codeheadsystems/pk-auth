// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.magiclink;

import com.codeheadsystems.pkauth.spi.ConsumedJtiStore;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.time.Duration;
import java.util.Objects;

/**
 * Caffeine-backed in-process {@link ConsumedJtiStore}.
 *
 * <p>Intended for development and single-instance use only. Production deployments with more than
 * one replica must replace this with a shared (Redis/DB-backed) {@link ConsumedJtiStore}
 * implementation: a token consumed on one replica is freely replayable on another within its TTL
 * window, because each replica tracks its own independent cache. {@link MagicLinkService} emits a
 * single startup WARN when this implementation is wired so the misconfiguration is visible in logs
 * before a production rollout.
 *
 * <p>The cache uses {@code expireAfterWrite} so entries are evicted at TTL relative to their first
 * (successful) insertion. The {@link #tryConsume(String, Duration)} contract (race-safe
 * check-and-set) is satisfied by {@code ConcurrentMap#putIfAbsent}, which is atomic.
 *
 * @since 0.9.1
 */
public final class InMemoryConsumedJtiStore implements ConsumedJtiStore {

  private final Cache<String, Boolean> consumedJtis;

  /**
   * Creates a new in-memory store.
   *
   * @param maxTtl upper bound on how long a consumed-JTI record is retained; entries written via
   *     {@link #tryConsume(String, Duration)} share this single expireAfterWrite policy regardless
   *     of the {@code ttl} argument passed at call time. Sized once at construction because
   *     Caffeine does not support per-entry TTLs without a more expensive eviction policy; callers
   *     should pass the largest TTL any consumer will request (typically {@code
   *     MagicLinkService.DEFAULT_CONSUMED_JTI_TTL}).
   * @since 0.9.1
   */
  public InMemoryConsumedJtiStore(Duration maxTtl) {
    Objects.requireNonNull(maxTtl, "maxTtl");
    this.consumedJtis = Caffeine.newBuilder().expireAfterWrite(maxTtl).build();
  }

  @Override
  public boolean tryConsume(String jti, Duration ttl) {
    Objects.requireNonNull(jti, "jti");
    Objects.requireNonNull(ttl, "ttl");
    Boolean previous = consumedJtis.asMap().putIfAbsent(jti, Boolean.TRUE);
    return previous == null;
  }
}
