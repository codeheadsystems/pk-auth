// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;

class StartResultTest {

  @Test
  void registrationStartedUnwrapsResponse() {
    StartRegistrationResponse response = mock(StartRegistrationResponse.class);
    StartRegistrationResult result = new StartRegistrationResult.Started(response);
    assertThat(result.responseOrThrow()).isSameAs(response);
  }

  @Test
  void registrationRateLimitedThrowsAndCarriesBucket() {
    StartRegistrationResult result = new StartRegistrationResult.RateLimited("ip");
    assertThat(((StartRegistrationResult.RateLimited) result).bucket()).isEqualTo("ip");
    assertThatThrownBy(result::responseOrThrow)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("ip");
  }

  @Test
  void authenticationStartedUnwrapsResponse() {
    StartAuthenticationResponse response = mock(StartAuthenticationResponse.class);
    StartAuthenticationResult result = new StartAuthenticationResult.Started(response);
    assertThat(result.responseOrThrow()).isSameAs(response);
  }

  @Test
  void authenticationRateLimitedThrowsAndCarriesBucket() {
    StartAuthenticationResult result = new StartAuthenticationResult.RateLimited("username");
    assertThat(((StartAuthenticationResult.RateLimited) result).bucket()).isEqualTo("username");
    assertThatThrownBy(result::responseOrThrow)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("username");
  }
}
