// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import org.junit.jupiter.api.Test;

/** Unit coverage for the Caffeine-backed sliding-window counter. */
class InMemoryWindowCounterTest {

  private final InMemoryWindowCounter counter = new InMemoryWindowCounter(Duration.ofMinutes(1));

  @Test
  void constructorRejectsNullZeroAndNegativeWindow() {
    assertThatThrownBy(() -> new InMemoryWindowCounter(null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new InMemoryWindowCounter(Duration.ZERO))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("window");
    assertThatThrownBy(() -> new InMemoryWindowCounter(Duration.ofSeconds(-1)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void firstIncrementStartsAtOneAndAccumulates() {
    assertThat(counter.countAndIncrement("k")).isEqualTo(1);
    assertThat(counter.countAndIncrement("k")).isEqualTo(2);
    assertThat(counter.countAndIncrement("k")).isEqualTo(3);
  }

  @Test
  void distinctKeysAreCountedIndependently() {
    counter.countAndIncrement("a");
    counter.countAndIncrement("a");
    counter.countAndIncrement("b");
    assertThat(counter.current("a")).isEqualTo(2);
    assertThat(counter.current("b")).isEqualTo(1);
  }

  @Test
  void currentReturnsZeroForUnseenKeyAndDoesNotIncrement() {
    assertThat(counter.current("absent")).isZero();
    assertThat(counter.current("absent")).isZero();
  }

  @Test
  void resetDropsAllCounters() {
    counter.countAndIncrement("a");
    counter.countAndIncrement("b");
    counter.reset();
    assertThat(counter.current("a")).isZero();
    assertThat(counter.current("b")).isZero();
    assertThat(counter.keys()).isEmpty();
  }

  @Test
  void keysReflectsTrackedCounters() {
    counter.countAndIncrement("a");
    counter.countAndIncrement("b");
    assertThat(counter.keys()).containsExactlyInAnyOrder("a", "b");
  }

  @Test
  void countAndIncrementAndCurrentRejectNullKey() {
    assertThatThrownBy(() -> counter.countAndIncrement(null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> counter.current(null)).isInstanceOf(NullPointerException.class);
  }
}
