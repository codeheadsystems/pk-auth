// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Server payload for {@code navigator.credentials.create()}. Mirrors the WebAuthn JSON Spec §5.1.3
 * "PublicKeyCredentialCreationOptionsJSON".
 *
 * <p>Privacy invariant: {@code excludeCredentials} is always non-null and is serialised as a JSON
 * array (possibly empty). Emitting {@code null} (or omitting the field) for brand-new users while
 * emitting a populated list for existing users would create an account-enumeration oracle on the
 * public {@code permitAll} start-registration endpoint. Callers must pass an empty list rather than
 * {@code null} when there are no credentials to exclude.
 *
 * @since 0.9.1
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record PublicKeyCredentialCreationOptionsJson(
    RelyingParty rp,
    UserInfo user,
    byte[] challenge,
    List<PublicKeyCredentialParameters> pubKeyCredParams,
    @Nullable Long timeout,
    List<PublicKeyCredentialDescriptor> excludeCredentials,
    @Nullable AuthenticatorSelectionCriteria authenticatorSelection,
    @Nullable AttestationConveyance attestation,
    @Nullable Map<String, Object> extensions) {

  public PublicKeyCredentialCreationOptionsJson {
    Objects.requireNonNull(rp, "rp");
    Objects.requireNonNull(user, "user");
    Objects.requireNonNull(challenge, "challenge");
    Objects.requireNonNull(pubKeyCredParams, "pubKeyCredParams");
    challenge = challenge.clone();
    pubKeyCredParams = List.copyOf(pubKeyCredParams);
    // Defensive default: deserialization of legacy payloads that omit the field arrives as null
    // here. Producers MUST pass a (possibly empty) list — the privacy invariant lives at the
    // service layer; this defaulting only protects deserialization round-trips.
    excludeCredentials = excludeCredentials == null ? List.of() : List.copyOf(excludeCredentials);
    if (extensions != null) {
      extensions = Map.copyOf(extensions);
    }
  }

  @Override
  public byte[] challenge() {
    return challenge.clone();
  }

  /** WebAuthn {@code PublicKeyCredentialRpEntity}. */
  public record RelyingParty(String id, String name) {
    public RelyingParty {
      Objects.requireNonNull(id, "id");
      Objects.requireNonNull(name, "name");
    }
  }

  /** WebAuthn {@code PublicKeyCredentialUserEntityJSON}. */
  public record UserInfo(byte[] id, String name, String displayName) {
    public UserInfo {
      Objects.requireNonNull(id, "id");
      Objects.requireNonNull(name, "name");
      Objects.requireNonNull(displayName, "displayName");
      id = id.clone();
    }

    @Override
    public byte[] id() {
      return id.clone();
    }
  }

  /** WebAuthn {@code PublicKeyCredentialParameters}. */
  public record PublicKeyCredentialParameters(String type, long alg) {
    public PublicKeyCredentialParameters {
      Objects.requireNonNull(type, "type");
    }
  }

  /** WebAuthn {@code PublicKeyCredentialDescriptorJSON}. */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record PublicKeyCredentialDescriptor(
      String type, byte[] id, @Nullable List<String> transports) {
    public PublicKeyCredentialDescriptor {
      Objects.requireNonNull(type, "type");
      Objects.requireNonNull(id, "id");
      id = id.clone();
      if (transports != null) {
        transports = List.copyOf(transports);
      }
    }

    @Override
    public byte[] id() {
      return id.clone();
    }
  }

  /** WebAuthn {@code AuthenticatorSelectionCriteria}. */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record AuthenticatorSelectionCriteria(
      @Nullable AuthenticatorAttachment authenticatorAttachment,
      @Nullable ResidentKeyRequirement residentKey,
      @Nullable Boolean requireResidentKey,
      @Nullable UserVerificationRequirement userVerification) {}
}
