// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.credential;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AuthenticatorDataTest {

  @Test
  void copiesRawAndExposesFlags() {
    byte[] raw = {1, 2, 3};
    AuthenticatorData data = new AuthenticatorData(raw, true, true, false, false, true, false, 5L);
    raw[0] = 99;
    assertThat(data.raw()[0]).isEqualTo((byte) 1);
    assertThat(data.userPresent()).isTrue();
    assertThat(data.userVerified()).isTrue();
    assertThat(data.signCount()).isEqualTo(5L);
    assertThat(data.toString())
        .contains("signCount=5")
        .contains("UP=true")
        .contains("UV=true")
        .contains("BE=false");
  }

  @Test
  void equalsAndHashCode() {
    AuthenticatorData a =
        new AuthenticatorData(new byte[] {1}, true, true, false, false, true, false, 1L);
    AuthenticatorData b =
        new AuthenticatorData(new byte[] {1}, true, true, false, false, true, false, 1L);
    AuthenticatorData c =
        new AuthenticatorData(new byte[] {2}, true, true, false, false, true, false, 1L);
    assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    assertThat(a).isNotEqualTo(c);
    assertThat(a).isNotEqualTo("string");
  }
}
