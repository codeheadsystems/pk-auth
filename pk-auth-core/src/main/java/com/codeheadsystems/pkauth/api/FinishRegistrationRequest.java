// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Host-app input for finishing a registration ceremony. The {@code challengeId} ties this request
 * back to the {@link PublicKeyCredentialCreationOptionsJson} previously issued by {@code
 * startRegistration}.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record FinishRegistrationRequest(
    ChallengeId challengeId,
    String username,
    @Nullable String label,
    RegistrationResponseJson response) {

  public FinishRegistrationRequest {
    Objects.requireNonNull(challengeId, "challengeId");
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(response, "response");
    if (username.isBlank()) {
      throw new IllegalArgumentException("username must be non-blank");
    }
  }
}
