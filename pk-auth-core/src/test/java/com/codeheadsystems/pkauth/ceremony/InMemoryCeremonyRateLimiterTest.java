// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.ceremony;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import org.junit.jupiter.api.Test;

/** Direct unit coverage for the in-memory ceremony rate limiter and its two counter buckets. */
class InMemoryCeremonyRateLimiterTest {

  @Test
  void defaultConstructorUsesDocumentedAllowances() {
    InMemoryCeremonyRateLimiter limiter = new InMemoryCeremonyRateLimiter();
    // First DEFAULT_PER_USERNAME_LIMIT acquisitions for a username succeed; the next one trips.
    for (int i = 0; i < InMemoryCeremonyRateLimiter.DEFAULT_PER_USERNAME_LIMIT; i++) {
      assertThat(limiter.tryAcquireForUsername("alice")).as("call %d", i).isTrue();
    }
    assertThat(limiter.tryAcquireForUsername("alice")).isFalse();
  }

  @Test
  void perIpLimitTripsAfterAllowanceExhausted() {
    InMemoryCeremonyRateLimiter limiter =
        new InMemoryCeremonyRateLimiter(2, 5, Duration.ofMinutes(1));
    assertThat(limiter.tryAcquireForIp("1.2.3.4")).isTrue();
    assertThat(limiter.tryAcquireForIp("1.2.3.4")).isTrue();
    assertThat(limiter.tryAcquireForIp("1.2.3.4")).isFalse();
    // A different IP has its own bucket.
    assertThat(limiter.tryAcquireForIp("5.6.7.8")).isTrue();
  }

  @Test
  void nullOrEmptyIpIsAllowedWithoutThrottling() {
    InMemoryCeremonyRateLimiter limiter =
        new InMemoryCeremonyRateLimiter(1, 1, Duration.ofMinutes(1));
    // Both bypass the bucket entirely, so repeated calls keep returning true.
    assertThat(limiter.tryAcquireForIp(null)).isTrue();
    assertThat(limiter.tryAcquireForIp(null)).isTrue();
    assertThat(limiter.tryAcquireForIp("")).isTrue();
    assertThat(limiter.tryAcquireForIp("")).isTrue();
    assertThat(limiter.ipKeys()).isEmpty();
  }

  @Test
  void usernameAcquireRejectsNull() {
    InMemoryCeremonyRateLimiter limiter = new InMemoryCeremonyRateLimiter();
    assertThatThrownBy(() -> limiter.tryAcquireForUsername(null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void constructorValidatesLimitsAndWindow() {
    assertThatThrownBy(() -> new InMemoryCeremonyRateLimiter(0, 5, Duration.ofMinutes(1)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("perIpLimit");
    assertThatThrownBy(() -> new InMemoryCeremonyRateLimiter(5, 0, Duration.ofMinutes(1)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("perUsernameLimit");
    assertThatThrownBy(() -> new InMemoryCeremonyRateLimiter(5, 5, null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new InMemoryCeremonyRateLimiter(5, 5, Duration.ZERO))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("window");
  }

  @Test
  void diagnosticKeyAccessorsAndResetTrackState() {
    InMemoryCeremonyRateLimiter limiter =
        new InMemoryCeremonyRateLimiter(5, 5, Duration.ofMinutes(1));
    limiter.tryAcquireForIp("9.9.9.9");
    limiter.tryAcquireForUsername("bob");
    assertThat(limiter.ipKeys()).containsExactly("9.9.9.9");
    assertThat(limiter.usernameKeys()).containsExactly("bob");

    limiter.reset();
    assertThat(limiter.ipKeys()).isEmpty();
    assertThat(limiter.usernameKeys()).isEmpty();
  }
}
