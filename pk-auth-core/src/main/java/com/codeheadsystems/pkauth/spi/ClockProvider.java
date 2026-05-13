// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import java.time.Clock;
import java.time.Instant;

/**
 * Indirection over {@link Clock} so ceremony logic stays testable. Adapters wire either the default
 * system clock or a controllable test clock.
 */
@FunctionalInterface
public interface ClockProvider {

  Instant now();

  /** Default provider backed by the system UTC clock. */
  static ClockProvider system() {
    return Instant::now;
  }

  /** Provider backed by an arbitrary {@link Clock}, useful for fixed-time tests. */
  static ClockProvider fromClock(Clock clock) {
    return () -> Instant.now(clock);
  }
}
