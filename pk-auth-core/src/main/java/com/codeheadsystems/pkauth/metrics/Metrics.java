// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.metrics;

import java.time.Duration;
import java.util.Objects;

/**
 * Tiny metrics facade with two implementations: a no-op default and a Micrometer-backed factory
 * activated only when {@code io.micrometer:micrometer-core} is on the runtime classpath. Phase 1
 * defines the shape; Phase 2 wires concrete counters in the ceremony service.
 */
public interface Metrics {

  /** Increment a counter, optionally tagged with key/value pairs. */
  void incrementCounter(String name, String... tags);

  /** Record a timing measurement. */
  void recordTimer(String name, Duration duration, String... tags);

  /** Returns a metrics implementation that drops every measurement. */
  static Metrics noop() {
    return NoopMetrics.INSTANCE;
  }

  /**
   * Returns a Micrometer-backed {@link Metrics} if {@code
   * io.micrometer.core.instrument.MeterRegistry} is on the classpath; otherwise falls back to
   * {@link #noop()}. Reflective load so the core module remains usable without Micrometer.
   */
  static Metrics micrometer(Object meterRegistry) {
    Objects.requireNonNull(meterRegistry, "meterRegistry");
    try {
      Class.forName("io.micrometer.core.instrument.MeterRegistry");
    } catch (ClassNotFoundException e) {
      return noop();
    }
    return new MicrometerMetrics(meterRegistry);
  }

  /** Singleton no-op implementation. */
  final class NoopMetrics implements Metrics {
    static final NoopMetrics INSTANCE = new NoopMetrics();

    private NoopMetrics() {}

    @Override
    public void incrementCounter(String name, String... tags) {
      // intentionally empty
    }

    @Override
    public void recordTimer(String name, Duration duration, String... tags) {
      // intentionally empty
    }
  }
}
