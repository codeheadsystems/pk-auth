// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh.spi;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

/** Locks the storage encoding for the {@code amr} list shared by every persistence adapter. */
class AmrTest {

  @Test
  void encodeJoinsWithComma() {
    assertThat(Amr.encode(List.of("pwd", "otp", "hwk"))).isEqualTo("pwd,otp,hwk");
  }

  @Test
  void encodeSingleHasNoSeparator() {
    assertThat(Amr.encode(List.of("user"))).isEqualTo("user");
  }

  @Test
  void decodeSplitsOnComma() {
    assertThat(Amr.decode("pwd,otp,hwk")).containsExactly("pwd", "otp", "hwk");
  }

  @Test
  void roundTripIsLossless() {
    List<String> amr = List.of("swk", "user", "mfa");
    assertThat(Amr.decode(Amr.encode(amr))).isEqualTo(amr);
  }

  @Test
  void decodeNullFallsBackToGenericUser() {
    assertThat(Amr.decode(null)).containsExactly("user");
  }

  @Test
  void decodeBlankFallsBackToGenericUser() {
    assertThat(Amr.decode("")).containsExactly("user");
    assertThat(Amr.decode("   ")).containsExactly("user");
  }
}
