// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.metrics;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import java.time.Duration;
import java.util.Objects;

/**
 * Micrometer-backed {@link Metrics} implementation. Constructed only via {@link
 * Metrics#micrometer(Object)} after a classpath check, so a runtime without Micrometer never loads
 * this class.
 */
final class MicrometerMetrics implements Metrics {

  private final MeterRegistry registry;

  MicrometerMetrics(Object meterRegistry) {
    this.registry = (MeterRegistry) Objects.requireNonNull(meterRegistry, "meterRegistry");
  }

  @Override
  public void incrementCounter(String name, String... tags) {
    registry.counter(name, Tags.of(tags)).increment();
  }

  @Override
  public void recordTimer(String name, Duration duration, String... tags) {
    registry.timer(name, Tags.of(tags)).record(duration);
  }
}
