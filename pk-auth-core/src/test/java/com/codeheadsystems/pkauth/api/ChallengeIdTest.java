// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class ChallengeIdTest {

  @Test
  void rejectsNullOrEmpty() {
    assertThatThrownBy(() -> new ChallengeId(null)).isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new ChallengeId("")).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void randomReturnsDistinctValues() {
    ChallengeId a = ChallengeId.random();
    ChallengeId b = ChallengeId.random();
    assertThat(a.value()).isNotBlank();
    assertThat(a).isNotEqualTo(b);
  }
}
