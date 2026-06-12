// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.Objects;

/**
 * Response envelope from {@code PasskeyAuthenticationService.startAuthentication}.
 *
 * <p>The browser only consumes {@code publicKey} (which the JS SDK passes to {@code
 * navigator.credentials.get({ publicKey })}). pk-auth's TS SDK additionally remembers the sibling
 * {@code challengeId} and includes it in the {@code FinishAuthenticationRequest}.
 *
 * @since 0.9.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record StartAuthenticationResponse(
    ChallengeId challengeId, PublicKeyCredentialRequestOptionsJson publicKey) {

  public StartAuthenticationResponse {
    Objects.requireNonNull(challengeId, "challengeId");
    Objects.requireNonNull(publicKey, "publicKey");
  }
}
