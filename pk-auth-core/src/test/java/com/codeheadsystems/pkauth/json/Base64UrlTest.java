// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.json;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class Base64UrlTest {

  @Test
  void emptyArrayRoundTrips() {
    assertThat(Base64Url.encode(new byte[0])).isEmpty();
    assertThat(Base64Url.decode("")).isEmpty();
  }

  @Test
  void singleByteHasNoPadding() {
    String encoded = Base64Url.encode(new byte[] {(byte) 0xff});
    assertThat(encoded).doesNotContain("=").isEqualTo("_w");
    assertThat(Base64Url.decode(encoded)).containsExactly(0xff);
  }

  @Test
  void leadingZeroBytesArePreserved() {
    byte[] bytes = {0x00, 0x00, 0x01, 0x02, 0x03};
    String enc = Base64Url.encode(bytes);
    assertThat(Base64Url.decode(enc)).containsExactly(bytes);
  }

  @Test
  void usesUrlSafeAlphabet() {
    // 0xFB 0xFF maps to "+/" in standard base64; ensure we get "-_" in URL-safe.
    byte[] bytes = {(byte) 0xfb, (byte) 0xff};
    String enc = Base64Url.encode(bytes);
    assertThat(enc).doesNotContain("+").doesNotContain("/").doesNotContain("=");
    assertThat(Base64Url.decode(enc)).containsExactly(0xfb, 0xff);
  }

  @Test
  void roundTripsAsciiText() {
    byte[] bytes = "hello world".getBytes(StandardCharsets.UTF_8);
    String enc = Base64Url.encode(bytes);
    assertThat(enc).doesNotContain("=");
    assertThat(Base64Url.decode(enc)).containsExactly(bytes);
  }

  @Test
  void tolersatesPaddedInput() {
    // Some clients send padding; we accept it for robustness.
    assertThat(Base64Url.decode("aGVsbG8="))
        .containsExactly("hello".getBytes(StandardCharsets.UTF_8));
  }

  @Test
  void rejectsNull() {
    assertThatThrownBy(() -> Base64Url.encode(null)).isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> Base64Url.decode(null)).isInstanceOf(NullPointerException.class);
  }
}
