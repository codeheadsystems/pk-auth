// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.ratelimit;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.time.Duration;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Caffeine-backed fixed-window counter shared by the backup-codes and magic-link rate limiters.
 *
 * <p>The window is fixed from a key's first increment, not sliding: {@code expireAfterWrite} starts
 * the clock when the key's counter is created, and the in-place {@link AtomicInteger} increments
 * that follow do not reset it, so the whole window expires at once {@code window} after the first
 * increment (the next increment then starts a fresh window at {@code 1}).
 *
 * <p>Each rate-limiter SPI in this project (e.g. {@code BackupCodeRateLimiter}, {@code
 * MagicLinkRateLimiter}, {@code CeremonyRateLimiter}) defines its own key signature. The
 * single-instance default implementation of each one composes a {@code String} key and delegates to
 * this counter — so the storage, TTL, and concurrency model is identical across features, while the
 * caller-facing interface stays specific to the feature.
 *
 * <p><strong>FOR DEV / SINGLE-INSTANCE USE ONLY.</strong> Production multi-instance deployments
 * MUST replace the per-feature default with a shared (Redis/DB-backed) implementation. Each replica
 * holds its own counter here, so the effective limit multiplies by the cluster size.
 *
 * @since 0.9.1
 */
public final class InMemoryWindowCounter {

  /**
   * Maximum tracked keys. {@code expireAfterWrite} alone retains every distinct key for the full
   * window, so a caller that varies its key (a submitted identifier, a source address) grows this
   * map with its own key variety rather than with the number of real users. Caffeine evicts
   * near-LRU entries at the cap; an evicted counter restarts, which costs at most one extra
   * allowance to the least-active key and never grants an unbounded budget to an active one.
   *
   * @since 2.3.0
   */
  public static final int DEFAULT_MAX_TRACKED_KEYS = 100_000;

  private final Cache<String, AtomicInteger> counters;

  /**
   * Creates a counter that drops keys after {@code window} has elapsed since their first increment,
   * retaining at most {@link #DEFAULT_MAX_TRACKED_KEYS} keys at any moment.
   *
   * @param window expiry-after-write window; must be positive
   */
  public InMemoryWindowCounter(Duration window) {
    Objects.requireNonNull(window, "window");
    if (window.isZero() || window.isNegative()) {
      throw new IllegalArgumentException("window must be positive");
    }
    this.counters =
        Caffeine.newBuilder()
            .expireAfterWrite(window)
            .maximumSize(DEFAULT_MAX_TRACKED_KEYS)
            .build();
  }

  /**
   * Increments the counter for {@code key} and returns the post-increment value. A key that has not
   * been seen, or whose previous window has expired, starts at {@code 1}.
   */
  public int countAndIncrement(String key) {
    Objects.requireNonNull(key, "key");
    AtomicInteger counter = counters.get(key, k -> new AtomicInteger());
    return counter.incrementAndGet();
  }

  /**
   * Returns the current count for {@code key} without incrementing it. {@code 0} if not present.
   */
  public int current(String key) {
    Objects.requireNonNull(key, "key");
    AtomicInteger counter = counters.getIfPresent(key);
    return counter == null ? 0 : counter.get();
  }

  /** Test helper: drops all tracked counters. */
  public void reset() {
    counters.invalidateAll();
  }

  /** Diagnostic accessor: snapshot of the active key set. */
  public Set<String> keys() {
    return new HashSet<>(counters.asMap().keySet());
  }
}
