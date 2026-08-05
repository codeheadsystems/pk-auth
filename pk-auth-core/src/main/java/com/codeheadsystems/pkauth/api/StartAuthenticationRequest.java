// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.jspecify.annotations.Nullable;

/**
 * Host-app input for starting an authentication ceremony. A null {@code username} allows
 * usernameless / discoverable-credential flows.
 *
 * @since 0.9.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record StartAuthenticationRequest(
    @Nullable String username, @Nullable UserVerificationRequirement userVerification) {

  /**
   * Rejects a username longer than {@link StartRegistrationRequest#MAX_USERNAME_LENGTH}. A {@code
   * null} username is still valid — that is the usernameless / discoverable-credential flow. Blank
   * is deliberately NOT rejected here (unlike the registration request): an unknown username
   * already yields the same empty {@code allowCredentials} shape as a known one, so there is no
   * enumeration signal to protect, and tightening it would change existing behaviour for no
   * security gain.
   *
   * @since 2.3.0
   */
  public StartAuthenticationRequest {
    if (username != null && username.length() > StartRegistrationRequest.MAX_USERNAME_LENGTH) {
      throw new IllegalArgumentException(
          "username must be at most "
              + StartRegistrationRequest.MAX_USERNAME_LENGTH
              + " characters");
    }
  }
}
