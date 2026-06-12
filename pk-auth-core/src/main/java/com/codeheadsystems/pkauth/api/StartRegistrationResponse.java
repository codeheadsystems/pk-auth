// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.Objects;

/**
 * Response envelope from {@code PasskeyAuthenticationService.startRegistration}.
 *
 * <p>The browser only consumes {@code publicKey} (which the JS SDK passes to {@code
 * navigator.credentials.create({ publicKey })}). pk-auth's TS SDK additionally remembers the
 * sibling {@code challengeId} and includes it in the {@code FinishRegistrationRequest}.
 *
 * @since 0.9.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record StartRegistrationResponse(
    ChallengeId challengeId, PublicKeyCredentialCreationOptionsJson publicKey) {

  public StartRegistrationResponse {
    Objects.requireNonNull(challengeId, "challengeId");
    Objects.requireNonNull(publicKey, "publicKey");
  }
}
