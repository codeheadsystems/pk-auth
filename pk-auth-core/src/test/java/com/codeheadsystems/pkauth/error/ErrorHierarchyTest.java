// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.error;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ErrorHierarchyTest {

  @Test
  void configurationExceptionCarriesCode() {
    ConfigurationException ex = new ConfigurationException("missing rp");
    assertThat(ex.errorCode()).isEqualTo(PkAuthErrorCode.CONFIGURATION);
    assertThat(ex.getMessage()).isEqualTo("missing rp");

    Throwable cause = new RuntimeException("inner");
    ConfigurationException withCause = new ConfigurationException("wrap", cause);
    assertThat(withCause.getCause()).isSameAs(cause);
  }

  @Test
  void illegalStateException() {
    IllegalPkAuthStateException ex = new IllegalPkAuthStateException("bad state");
    assertThat(ex.errorCode()).isEqualTo(PkAuthErrorCode.ILLEGAL_STATE);
    Throwable cause = new RuntimeException("inner");
    assertThat(new IllegalPkAuthStateException("x", cause).getCause()).isSameAs(cause);
  }

  @Test
  void errorCodesHaveStableStrings() {
    assertThat(PkAuthErrorCode.CONFIGURATION.code()).isEqualTo("pkauth.configuration");
    assertThat(PkAuthErrorCode.CHALLENGE_NOT_FOUND.code()).isEqualTo("pkauth.challenge.not_found");
    assertThat(PkAuthErrorCode.CREDENTIAL_DUPLICATE.code())
        .isEqualTo("pkauth.credential.duplicate");
    // Every enum constant returns a non-blank, dotted code.
    for (PkAuthErrorCode c : PkAuthErrorCode.values()) {
      assertThat(c.code()).startsWith("pkauth.").doesNotContain(" ");
    }
  }
}
