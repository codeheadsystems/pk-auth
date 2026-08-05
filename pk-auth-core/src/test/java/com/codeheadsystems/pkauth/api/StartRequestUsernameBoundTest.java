// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/**
 * The username on the two {@code start*} requests is attacker-chosen on a {@code permitAll}
 * endpoint and outlives the request: it keys the per-username rate-limit bucket for the limiter's
 * whole window, and registration hands it to {@code UserLookup#getOrCreateHandle}, which persists a
 * user row before any credential exists. These bounds keep both proportional to real usage rather
 * than to whatever the caller sends.
 */
class StartRequestUsernameBoundTest {

  private static String ofLength(int n) {
    return "a".repeat(n);
  }

  @Test
  void registrationRejectsUsernameOverTheBound() {
    String tooLong = ofLength(StartRegistrationRequest.MAX_USERNAME_LENGTH + 1);
    assertThatThrownBy(() -> new StartRegistrationRequest(tooLong, "x", null, null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("at most");
  }

  @Test
  void registrationAcceptsUsernameExactlyAtTheBound() {
    String atLimit = ofLength(StartRegistrationRequest.MAX_USERNAME_LENGTH);
    assertThatCode(() -> new StartRegistrationRequest(atLimit, "x", null, null))
        .doesNotThrowAnyException();
  }

  @Test
  void authenticationRejectsUsernameOverTheBound() {
    String tooLong = ofLength(StartRegistrationRequest.MAX_USERNAME_LENGTH + 1);
    assertThatThrownBy(() -> new StartAuthenticationRequest(tooLong, null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("at most");
  }

  @Test
  void authenticationStillAcceptsNullUsernameForTheUsernamelessFlow() {
    assertThatCode(() -> new StartAuthenticationRequest(null, null)).doesNotThrowAnyException();
    assertThat(new StartAuthenticationRequest(null, null).username()).isNull();
  }

  @Test
  void authenticationAcceptsUsernameExactlyAtTheBound() {
    String atLimit = ofLength(StartRegistrationRequest.MAX_USERNAME_LENGTH);
    assertThatCode(() -> new StartAuthenticationRequest(atLimit, null)).doesNotThrowAnyException();
  }
}
