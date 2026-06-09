// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Covers both built-in {@link RefreshTtlPolicy} factories and their validation. */
class RefreshTtlPolicyTest {

  @Test
  void singleAppliesSameTtlToEveryAudienceAndKnowsNone() {
    RefreshTtlPolicy policy = RefreshTtlPolicy.single(Duration.ofDays(7));
    assertThat(policy.refreshTtl("web")).isEqualTo(Duration.ofDays(7));
    assertThat(policy.refreshTtl("cli")).isEqualTo(Duration.ofDays(7));
    assertThat(policy.knownAudiences()).isEmpty();
    assertThat(policy.toString()).contains("single");
  }

  @Test
  void singleRejectsNullZeroAndNegative() {
    assertThatThrownBy(() -> RefreshTtlPolicy.single(null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> RefreshTtlPolicy.single(Duration.ZERO))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> RefreshTtlPolicy.single(Duration.ofSeconds(-1)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void fixedDispatchesByAudienceWithDefaultFallback() {
    RefreshTtlPolicy policy =
        RefreshTtlPolicy.fixed(
            Duration.ofDays(14), Map.of("web", Duration.ofDays(14), "cli", Duration.ofDays(90)));
    assertThat(policy.refreshTtl("cli")).isEqualTo(Duration.ofDays(90));
    assertThat(policy.refreshTtl("web")).isEqualTo(Duration.ofDays(14));
    assertThat(policy.refreshTtl("unmapped")).isEqualTo(Duration.ofDays(14)); // default fallback
    assertThat(policy.knownAudiences()).containsExactlyInAnyOrder("web", "cli");
    assertThat(policy.toString()).contains("fixed");
  }

  @Test
  void fixedRejectsNullArguments() {
    assertThatThrownBy(() -> RefreshTtlPolicy.fixed(null, Map.of()))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> RefreshTtlPolicy.fixed(Duration.ofDays(1), null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void fixedRejectsNonPositiveDefault() {
    assertThatThrownBy(() -> RefreshTtlPolicy.fixed(Duration.ZERO, Map.of()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("defaultTtl");
  }

  @Test
  void fixedRejectsNonPositiveOverride() {
    assertThatThrownBy(
            () -> RefreshTtlPolicy.fixed(Duration.ofDays(1), Map.of("web", Duration.ofDays(-1))))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("web");
  }

  @Test
  void fixedRejectsNullKeyOrValueInOverrides() {
    Map<String, Duration> nullValue = new HashMap<>();
    nullValue.put("web", null);
    assertThatThrownBy(() -> RefreshTtlPolicy.fixed(Duration.ofDays(1), nullValue))
        .isInstanceOf(NullPointerException.class);

    Map<String, Duration> nullKey = new HashMap<>();
    nullKey.put(null, Duration.ofDays(1));
    assertThatThrownBy(() -> RefreshTtlPolicy.fixed(Duration.ofDays(1), nullKey))
        .isInstanceOf(NullPointerException.class);
  }
}
