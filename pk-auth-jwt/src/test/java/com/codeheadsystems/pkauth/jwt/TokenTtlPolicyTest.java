// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Validation and dispatch for both built-in {@link TokenTtlPolicy} factories. */
class TokenTtlPolicyTest {

  @Test
  void singleAppliesSameTtlAndKnowsNoAudiences() {
    TokenTtlPolicy policy = TokenTtlPolicy.single(Duration.ofMinutes(30));
    assertThat(policy.accessTtl("web")).isEqualTo(Duration.ofMinutes(30));
    assertThat(policy.accessTtl("anything")).isEqualTo(Duration.ofMinutes(30));
    assertThat(policy.knownAudiences()).isEmpty();
    assertThat(policy.toString()).contains("single");
  }

  @Test
  void singleRejectsNullZeroNegative() {
    assertThatThrownBy(() -> TokenTtlPolicy.single(null)).isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> TokenTtlPolicy.single(Duration.ZERO))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> TokenTtlPolicy.single(Duration.ofMinutes(-1)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void fixedDispatchesWithDefaultFallbackAndExposesKnownAudiences() {
    TokenTtlPolicy policy =
        TokenTtlPolicy.fixed(
            Duration.ofHours(1), Map.of("web", Duration.ofMinutes(15), "cli", Duration.ofHours(8)));
    assertThat(policy.accessTtl("web")).isEqualTo(Duration.ofMinutes(15));
    assertThat(policy.accessTtl("cli")).isEqualTo(Duration.ofHours(8));
    assertThat(policy.accessTtl("unmapped")).isEqualTo(Duration.ofHours(1));
    assertThat(policy.knownAudiences()).containsExactlyInAnyOrder("web", "cli");
    assertThat(policy.toString()).contains("fixed");
  }

  @Test
  void fixedRejectsNullArgumentsAndNonPositiveDurations() {
    assertThatThrownBy(() -> TokenTtlPolicy.fixed(null, Map.of()))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> TokenTtlPolicy.fixed(Duration.ofHours(1), null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> TokenTtlPolicy.fixed(Duration.ZERO, Map.of()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("defaultTtl");
    assertThatThrownBy(
            () -> TokenTtlPolicy.fixed(Duration.ofHours(1), Map.of("web", Duration.ZERO)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("web");
  }

  @Test
  void fixedRejectsNullKeyOrValue() {
    Map<String, Duration> nullValue = new HashMap<>();
    nullValue.put("web", null);
    assertThatThrownBy(() -> TokenTtlPolicy.fixed(Duration.ofHours(1), nullValue))
        .isInstanceOf(NullPointerException.class);
  }
}
