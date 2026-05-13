// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.Objects;

/** Host-app input for finishing an authentication ceremony. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record FinishAuthenticationRequest(
    ChallengeId challengeId, AuthenticationResponseJson response) {

  public FinishAuthenticationRequest {
    Objects.requireNonNull(challengeId, "challengeId");
    Objects.requireNonNull(response, "response");
  }
}
