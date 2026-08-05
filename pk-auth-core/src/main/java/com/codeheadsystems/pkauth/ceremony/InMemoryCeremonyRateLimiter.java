// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.ceremony;

import com.codeheadsystems.pkauth.spi.CeremonyRateLimiter;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.time.Duration;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple Caffeine-backed in-memory {@link CeremonyRateLimiter} suitable for single-instance / dev
 * deployments. Tracks two independent counter maps (per-IP and per-username), each expiring after a
 * configured window.
 *
 * <p><strong>FOR DEV / SINGLE-INSTANCE USE ONLY.</strong> Production deployments MUST replace this
 * with a shared (Redis/DB-backed) {@link CeremonyRateLimiter} implementation, otherwise per-replica
 * counters multiply by the cluster size. For example, with a limit of 30 starts per minute and a
 * 3-node cluster, an attacker can issue up to 90 starts per minute because each replica tracks its
 * own independent counter. Wire a production-grade implementation via the {@code
 * PasskeyAuthenticationServices.Builder#ceremonyRateLimiter(...)} seam.
 *
 * <p>The defaults are intentionally generous so legitimate UX (a user fumbling their authenticator,
 * a flaky network forcing a retry) does not trip the limiter, but are tight enough to throttle
 * single-source enumeration / brute-force at a meaningful rate. Hosts that want different limits
 * should construct this class with explicit values or supply their own SPI implementation.
 *
 * @since 0.9.1
 */
public final class InMemoryCeremonyRateLimiter implements CeremonyRateLimiter {

  /** Default per-IP allowance: 30 ceremony calls per minute. */
  public static final int DEFAULT_PER_IP_LIMIT = 30;

  /** Default per-username allowance: 10 start-ceremony calls per minute. */
  public static final int DEFAULT_PER_USERNAME_LIMIT = 10;

  /** Default window over which the per-IP and per-username counters are tracked. */
  public static final Duration DEFAULT_WINDOW = Duration.ofMinutes(1);

  /**
   * Maximum tracked keys per bucket map. Both maps are keyed by attacker-influenced values (source
   * IP, submitted username) on {@code permitAll} endpoints, and {@code expireAfterWrite} alone
   * retains every distinct key for the full window — so without a size bound the maps grow with the
   * caller's key variety, not with the number of real users. Caffeine evicts near-LRU entries at
   * the cap; an evicted counter simply restarts, which costs at most one extra allowance to the
   * least-active key and never grants an unbounded budget to an active one.
   *
   * @since 2.3.0
   */
  public static final int DEFAULT_MAX_TRACKED_KEYS = 100_000;

  private static final Logger LOG = LoggerFactory.getLogger(InMemoryCeremonyRateLimiter.class);

  private final int perIpLimit;
  private final int perUsernameLimit;
  private final Cache<String, AtomicInteger> ipCounters;
  private final Cache<String, AtomicInteger> usernameCounters;

  /**
   * Constructs a limiter with the default per-IP / per-username allowances and a 1-minute window.
   *
   * @since 0.9.1
   */
  public InMemoryCeremonyRateLimiter() {
    this(DEFAULT_PER_IP_LIMIT, DEFAULT_PER_USERNAME_LIMIT, DEFAULT_WINDOW);
  }

  /**
   * Constructs a limiter with explicit per-IP / per-username allowances and a window over which the
   * counters expire.
   *
   * @param perIpLimit maximum ceremony calls allowed from one IP per {@code window}; must be {@code
   *     > 0}
   * @param perUsernameLimit maximum start-ceremony calls allowed for one username per {@code
   *     window}; must be {@code > 0}
   * @param window window over which counters reset (must be non-null and strictly positive)
   * @since 0.9.1
   */
  public InMemoryCeremonyRateLimiter(int perIpLimit, int perUsernameLimit, Duration window) {
    if (perIpLimit <= 0) {
      throw new IllegalArgumentException("perIpLimit must be > 0");
    }
    if (perUsernameLimit <= 0) {
      throw new IllegalArgumentException("perUsernameLimit must be > 0");
    }
    Objects.requireNonNull(window, "window");
    if (window.isZero() || window.isNegative()) {
      throw new IllegalArgumentException("window must be strictly positive");
    }
    this.perIpLimit = perIpLimit;
    this.perUsernameLimit = perUsernameLimit;
    this.ipCounters =
        Caffeine.newBuilder()
            .expireAfterWrite(window)
            .maximumSize(DEFAULT_MAX_TRACKED_KEYS)
            .build();
    this.usernameCounters =
        Caffeine.newBuilder()
            .expireAfterWrite(window)
            .maximumSize(DEFAULT_MAX_TRACKED_KEYS)
            .build();
    LOG.warn(
        "ceremony.rate-limiter InMemoryCeremonyRateLimiter instantiated (perIp={} perUsername={}"
            + " window={}) — FOR DEV / SINGLE-INSTANCE USE ONLY. Production deployments with more"
            + " than one replica MUST inject a shared (Redis/DB-backed) CeremonyRateLimiter via"
            + " the PasskeyAuthenticationServices.Builder seam, otherwise per-replica counters"
            + " multiply by the cluster size.",
        perIpLimit,
        perUsernameLimit,
        window);
  }

  @Override
  public boolean tryAcquireForIp(@Nullable String ip) {
    if (ip == null || ip.isEmpty()) {
      // Unknown source; cannot meaningfully throttle. Allow through — the per-username bucket
      // still protects the named-user surface; for usernameless calls the host should run behind
      // an LB that supplies a stable client IP.
      return true;
    }
    return acquire(ipCounters, ip, perIpLimit);
  }

  @Override
  public boolean tryAcquireForUsername(String username) {
    Objects.requireNonNull(username, "username");
    return acquire(usernameCounters, username, perUsernameLimit);
  }

  private static boolean acquire(Cache<String, AtomicInteger> cache, String key, int limit) {
    AtomicInteger counter = cache.get(key, k -> new AtomicInteger());
    int next = counter.incrementAndGet();
    return next <= limit;
  }

  /**
   * Test helper that drops all tracked counters. Not part of the {@link CeremonyRateLimiter}
   * contract; provided so tests can run cases in isolation.
   *
   * @since 0.9.1
   */
  public void reset() {
    ipCounters.invalidateAll();
    usernameCounters.invalidateAll();
  }

  /**
   * Diagnostic accessor returning the currently-tracked IP keys.
   *
   * @return snapshot of live IP keys
   * @since 0.9.1
   */
  public Set<String> ipKeys() {
    return new HashSet<>(ipCounters.asMap().keySet());
  }

  /**
   * Diagnostic accessor returning the currently-tracked username keys.
   *
   * @return snapshot of live username keys
   * @since 0.9.1
   */
  public Set<String> usernameKeys() {
    return new HashSet<>(usernameCounters.asMap().keySet());
  }
}
