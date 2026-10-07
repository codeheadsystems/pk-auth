// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import java.time.Duration;

/**
 * Host-app integration point that records the JTI (JWT id) values of single-use tokens (magic-link
 * tokens, primarily) so a captured token cannot be replayed inside its TTL window.
 *
 * <p>The contract is a single atomic operation: {@link #tryConsume(String, Duration)} returns
 * {@code true} the first time a given {@code jti} is presented and {@code false} on every
 * subsequent call within the TTL. Implementations must make this check-and-set race-safe;
 * concurrent calls with the same {@code jti} must observe exactly one {@code true} return.
 *
 * <p>Production deployments with more than one replica must override this SPI with a shared,
 * race-safe store (Redis {@code SET NX EX}, a database row with a unique index, etc.). The default
 * implementation supplied by pk-auth ({@code InMemoryConsumedJtiStore}) tracks state in a
 * per-process Caffeine cache and is for single-instance or development use only, so a magic-link
 * consumed on replica A is freely replayable on replica B within its TTL.
 *
 * <p>This SPI mirrors the {@code MagicLinkRateLimiter} pattern: pk-auth ships a Caffeine-backed
 * default suitable for dev / single-node deployments, and {@code MagicLinkService} (or equivalent)
 * emits a startup WARN when the in-memory default is wired so operators notice before a production
 * rollout.
 *
 * @since 0.9.1
 */
@FunctionalInterface
public interface ConsumedJtiStore {

  /**
   * Records {@code jti} as consumed and returns whether this call observed it for the first time.
   *
   * @param jti the JWT id of the token being consumed; must be non-null and non-empty
   * @param ttl how long the record must be retained; should be at least the JWT's remaining
   *     lifetime plus any validator clock-skew tolerance, otherwise an expired-but-still-accepted
   *     token could be replayed
   * @return {@code true} if this {@code jti} had not previously been recorded and is now stored;
   *     {@code false} if it was already present (i.e., a replay attempt)
   * @since 0.9.1
   */
  boolean tryConsume(String jti, Duration ttl);
}
