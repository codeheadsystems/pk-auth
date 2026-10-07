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
 *
 * <p>Privacy invariant: {@code allowCredentials} is always non-null and is serialised as a JSON
 * array (possibly empty). Emitting {@code null} (or omitting the field) for unknown users while
 * emitting a populated list for known users would create an account-enumeration oracle on the
 * public {@code permitAll} start-authentication endpoint. Callers must pass an empty list rather
 * than {@code null} when there are no credentials to allow.
 *
 * @since 0.9.1
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record PublicKeyCredentialRequestOptionsJson(
    byte[] challenge,
    @Nullable Long timeout,
    @Nullable String rpId,
    List<PublicKeyCredentialDescriptor> allowCredentials,
    @Nullable UserVerificationRequirement userVerification,
    @Nullable Map<String, Object> extensions) {

  public PublicKeyCredentialRequestOptionsJson {
    Objects.requireNonNull(challenge, "challenge");
    challenge = challenge.clone();
    // Defensive default: deserialization of legacy payloads that omit the field arrives as null
    // here. Producers MUST pass a (possibly empty) list — the privacy invariant lives at the
    // service layer; this defaulting only protects deserialization round-trips.
    allowCredentials = allowCredentials == null ? List.of() : List.copyOf(allowCredentials);
    if (extensions != null) {
      extensions = Map.copyOf(extensions);
    }
  }

  @Override
  public byte[] challenge() {
    return challenge.clone();
  }
}
