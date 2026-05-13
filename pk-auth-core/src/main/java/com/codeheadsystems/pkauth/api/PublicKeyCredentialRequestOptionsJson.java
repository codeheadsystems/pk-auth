// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import com.codeheadsystems.pkauth.api.PublicKeyCredentialCreationOptionsJson.PublicKeyCredentialDescriptor;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Server payload for {@code navigator.credentials.get()}. Mirrors the WebAuthn JSON Spec §5.1.4
 * "PublicKeyCredentialRequestOptionsJSON".
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record PublicKeyCredentialRequestOptionsJson(
    byte[] challenge,
    @Nullable Long timeout,
    @Nullable String rpId,
    @Nullable List<PublicKeyCredentialDescriptor> allowCredentials,
    @Nullable UserVerificationRequirement userVerification,
    @Nullable Map<String, Object> extensions) {

  public PublicKeyCredentialRequestOptionsJson {
    Objects.requireNonNull(challenge, "challenge");
    challenge = challenge.clone();
    if (allowCredentials != null) {
      allowCredentials = List.copyOf(allowCredentials);
    }
    if (extensions != null) {
      extensions = Map.copyOf(extensions);
    }
  }

  @Override
  public byte[] challenge() {
    return challenge.clone();
  }
}
