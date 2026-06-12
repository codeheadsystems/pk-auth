// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import java.time.Clock;
import java.time.Instant;

/**
 * Indirection over {@link Clock} so ceremony logic stays testable. Adapters wire either the default
 * system clock or a controllable test clock.
 *
 * @since 0.9.0
 */
@FunctionalInterface
public interface ClockProvider {

  /**
   * Returns the current instant. Injecting this (rather than calling {@link Instant#now()}
   * directly) lets tests drive ceremony/expiry timing deterministically.
   *
   * @return the current instant per this provider's clock.
   * @since 0.9.0
   */
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
