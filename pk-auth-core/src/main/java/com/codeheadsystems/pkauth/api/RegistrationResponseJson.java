// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Browser-returned payload for a registration ceremony. Mirrors WebAuthn JSON Spec §5.1.3
 * "RegistrationResponseJSON".
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record RegistrationResponseJson(
    byte[] id,
    byte[] rawId,
    AuthenticatorAttestationResponseJson response,
    @Nullable AuthenticatorAttachment authenticatorAttachment,
    @Nullable Map<String, Object> clientExtensionResults,
    String type) {

  public RegistrationResponseJson {
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

  /** WebAuthn {@code AuthenticatorAttestationResponseJSON}. */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record AuthenticatorAttestationResponseJson(
      byte[] clientDataJSON,
      byte[] attestationObject,
      @Nullable List<String> transports,
      byte @Nullable [] authenticatorData,
      byte @Nullable [] publicKey,
      @Nullable Long publicKeyAlgorithm) {

    public AuthenticatorAttestationResponseJson {
      Objects.requireNonNull(clientDataJSON, "clientDataJSON");
      Objects.requireNonNull(attestationObject, "attestationObject");
      clientDataJSON = clientDataJSON.clone();
      attestationObject = attestationObject.clone();
      if (transports != null) {
        transports = List.copyOf(transports);
      }
      if (authenticatorData != null) {
        authenticatorData = authenticatorData.clone();
      }
      if (publicKey != null) {
        publicKey = publicKey.clone();
      }
    }

    @Override
    public byte[] clientDataJSON() {
      return clientDataJSON.clone();
    }

    @Override
    public byte[] attestationObject() {
      return attestationObject.clone();
    }

    @Override
    public byte @Nullable [] authenticatorData() {
      return authenticatorData == null ? null : authenticatorData.clone();
    }

    @Override
    public byte @Nullable [] publicKey() {
      return publicKey == null ? null : publicKey.clone();
    }
  }
}
