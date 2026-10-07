// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.json.PkAuthObjectMappers;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

/**
 * Locks the shared response wire shapes so any adapter that returns them produces byte-for-byte
 * identical JSON.
 */
class AdminResponseShapesTest {

  @Test
  void emailVerificationResultRejectsNullHandle() {
    assertThatThrownBy(() -> new EmailVerificationResult(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessageContaining("userHandle");
  }

  /**
   * Locks the JSON wire shape that promoted the per-adapter ad-hoc encoding: {@code
   * {"userHandle":"<base64url>"}}. The pk-auth Jackson module is responsible for emitting {@link
   * UserHandle} as a base64url string; adapter call-sites no longer call {@code
   * Base64Url.encode(...)} explicitly.
   */
  @Test
  void emailVerificationResultSerialisesUserHandleAsBase64UrlString() {
    JsonMapper mapper = PkAuthObjectMappers.create();
    UserHandle uh = UserHandle.of(new byte[] {1, 2, 3});
    String json = mapper.writeValueAsString(new EmailVerificationResult(uh));
    assertThat(json).isEqualTo("{\"userHandle\":\"" + Base64Url.encode(uh.value()) + "\"}");
  }
}
