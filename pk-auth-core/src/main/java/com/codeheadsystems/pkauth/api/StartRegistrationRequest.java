// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/** Host-app input for starting a registration ceremony. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record StartRegistrationRequest(
    String username,
    @Nullable String displayName,
    @Nullable String label,
    @Nullable UserVerificationRequirement userVerification) {

  public StartRegistrationRequest {
    Objects.requireNonNull(username, "username");
    if (username.isBlank()) {
      throw new IllegalArgumentException("username must be non-blank");
    }
  }
}
