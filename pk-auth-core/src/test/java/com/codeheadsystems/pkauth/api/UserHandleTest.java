// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class UserHandleTest {

  @Test
  void defensivelyCopiesOnConstructionAndAccess() {
    byte[] source = {1, 2, 3, 4};
    UserHandle handle = new UserHandle(source);
    source[0] = 99;
    assertThat(handle.value()[0]).isEqualTo((byte) 1);

    byte[] read = handle.value();
    read[0] = 77;
    assertThat(handle.value()[0]).isEqualTo((byte) 1);
  }

  @Test
  void equalsAndHashCodeUseContent() {
    UserHandle a = new UserHandle(new byte[] {1, 2, 3});
    UserHandle b = new UserHandle(new byte[] {1, 2, 3});
    UserHandle c = new UserHandle(new byte[] {1, 2, 4});

    assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    assertThat(a).isNotEqualTo(c);
    assertThat(a).isNotEqualTo("not a user handle");
  }

  @Test
  void rejectsNullAndOutOfRangeLengths() {
    assertThatThrownBy(() -> new UserHandle(null)).isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new UserHandle(new byte[0]))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new UserHandle(new byte[65]))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void factoryAndRandom() {
    UserHandle r1 = UserHandle.random();
    UserHandle r2 = UserHandle.random();
    assertThat(r1.value()).hasSize(16);
    assertThat(r1).isNotEqualTo(r2);
    assertThat(UserHandle.of(new byte[] {7})).isEqualTo(new UserHandle(new byte[] {7}));
  }

  @Test
  void toStringIsHex() {
    UserHandle h = new UserHandle(new byte[] {0x0a, 0x0b, 0x0c});
    assertThat(h.toString()).contains("0a0b0c");
  }
}
