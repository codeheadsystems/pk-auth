// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.metrics;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Duration;
import org.junit.jupiter.api.Test;

class MetricsTest {

  @Test
  void noopAcceptsAnythingAndIsSingleton() {
    Metrics m = Metrics.noop();
    assertThat(m).isSameAs(Metrics.noop());
    m.incrementCounter("anything");
    m.recordTimer("anything", Duration.ofMillis(1), "tag", "value");
  }

  @Test
  void micrometerWrapsRegistryWhenAvailable() {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    Metrics m = Metrics.micrometer(registry);

    m.incrementCounter("ceremony.outcome", "result", "success");
    m.recordTimer("ceremony.duration", Duration.ofMillis(5), "phase", "register");

    assertThat(registry.counter("ceremony.outcome", "result", "success").count()).isEqualTo(1.0);
    assertThat(registry.timer("ceremony.duration", "phase", "register").count()).isEqualTo(1);
  }

  @Test
  void micrometerRejectsNullRegistry() {
    assertThatThrownBy(() -> Metrics.micrometer(null)).isInstanceOf(NullPointerException.class);
  }
}
