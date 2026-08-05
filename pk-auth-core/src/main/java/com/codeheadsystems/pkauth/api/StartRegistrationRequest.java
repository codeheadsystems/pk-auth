// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Host-app input for starting a registration ceremony.
 *
 * @since 0.9.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record StartRegistrationRequest(
    String username,
    @Nullable String displayName,
    @Nullable String label,
    @Nullable UserVerificationRequirement userVerification) {

  /**
   * Maximum accepted length of {@link #username}, in {@code char}s.
   *
   * <p>The username is attacker-chosen on this {@code permitAll} endpoint and is retained well
   * beyond the request: it keys the per-username rate-limit bucket for the limiter's whole window,
   * and {@code startRegistration} passes it to {@link
   * com.codeheadsystems.pkauth.spi.UserLookup#getOrCreateHandle} — which persists a user row before
   * any credential exists. Unbounded, both of those grow with whatever the caller sends. 256
   * comfortably covers an email address used as a username.
   *
   * @since 2.3.0
   */
  public static final int MAX_USERNAME_LENGTH = 256;

  public StartRegistrationRequest {
    Objects.requireNonNull(username, "username");
    if (username.isBlank()) {
      throw new IllegalArgumentException("username must be non-blank");
    }
    if (username.length() > MAX_USERNAME_LENGTH) {
      throw new IllegalArgumentException(
          "username must be at most " + MAX_USERNAME_LENGTH + " characters");
    }
  }
}
