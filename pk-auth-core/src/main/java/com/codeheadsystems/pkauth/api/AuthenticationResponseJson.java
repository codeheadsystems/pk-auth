// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Browser-returned payload for an authentication ceremony. Mirrors WebAuthn JSON Spec §5.1.4
 * "AuthenticationResponseJSON".
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthenticationResponseJson(
    byte[] id,
    byte[] rawId,
    AuthenticatorAssertionResponseJson response,
    @Nullable AuthenticatorAttachment authenticatorAttachment,
    @Nullable Map<String, Object> clientExtensionResults,
    String type) {

  public AuthenticationResponseJson {
    Objects.requireNonNull(id, "id");
    Objects.requireNonNull(rawId, "rawId");
    Objects.requireNonNull(response, "response");
    Objects.requireNonNull(type, "type");
    id = id.clone();
    rawId = rawId.clone();
    if (clientExtensionResults != null) {
      clientExtensionResults = Map.copyOf(clientExtensionResults);
    }
  }

  @Override
  public byte[] id() {
    return id.clone();
  }

  @Override
  public byte[] rawId() {
    return rawId.clone();
  }

  /** WebAuthn {@code AuthenticatorAssertionResponseJSON}. */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record AuthenticatorAssertionResponseJson(
      byte[] clientDataJSON,
      byte[] authenticatorData,
      byte[] signature,
      byte @Nullable [] userHandle) {

    public AuthenticatorAssertionResponseJson {
      Objects.requireNonNull(clientDataJSON, "clientDataJSON");
      Objects.requireNonNull(authenticatorData, "authenticatorData");
      Objects.requireNonNull(signature, "signature");
      clientDataJSON = clientDataJSON.clone();
      authenticatorData = authenticatorData.clone();
      signature = signature.clone();
      if (userHandle != null) {
        userHandle = userHandle.clone();
      }
    }

    @Override
    public byte[] clientDataJSON() {
      return clientDataJSON.clone();
    }

    @Override
    public byte[] authenticatorData() {
      return authenticatorData.clone();
    }

    @Override
    public byte[] signature() {
      return signature.clone();
    }

    @Override
    public byte @Nullable [] userHandle() {
      return userHandle == null ? null : userHandle.clone();
    }
  }
}
