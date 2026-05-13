// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import com.codeheadsystems.pkauth.credential.AuthenticatorData;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Closed sum of outcomes from {@code PasskeyAuthenticationService.finishRegistration}. Mapped to
 * HTTP responses by adapter modules.
 */
public sealed interface RegistrationResult {

  /** Registration succeeded; the newly-created credential is ready to persist. */
  record Success(CredentialRecord credential, AuthenticatorData authenticatorData)
      implements RegistrationResult {
    public Success {
      Objects.requireNonNull(credential, "credential");
      Objects.requireNonNull(authenticatorData, "authenticatorData");
    }
  }

  /** Challenge missing, expired, or mismatched against the stored challenge. */
  record InvalidChallenge(String detail) implements RegistrationResult {
    public InvalidChallenge {
      Objects.requireNonNull(detail, "detail");
    }
  }

  /** Client-reported origin did not match an allowed origin from {@code RelyingPartyConfig}. */
  record OriginMismatch(String expected, String actual) implements RegistrationResult {
    public OriginMismatch {
      Objects.requireNonNull(expected, "expected");
      Objects.requireNonNull(actual, "actual");
    }
  }

  /** Attestation policy rejected the authenticator's attestation statement. */
  record AttestationRejected(String reason) implements RegistrationResult {
    public AttestationRejected {
      Objects.requireNonNull(reason, "reason");
    }
  }

  /** A credential with the same id is already registered. */
  record DuplicateCredential(byte[] credentialId) implements RegistrationResult {
    public DuplicateCredential {
      Objects.requireNonNull(credentialId, "credentialId");
      credentialId = credentialId.clone();
    }

    @Override
    public byte[] credentialId() {
      return credentialId.clone();
    }

    @Override
    public boolean equals(Object o) {
      return o instanceof DuplicateCredential other
          && Arrays.equals(this.credentialId, other.credentialId);
    }

    @Override
    public int hashCode() {
      return Arrays.hashCode(credentialId);
    }

    @Override
    public String toString() {
      return "DuplicateCredential[credentialId=" + HexFormat.of().formatHex(credentialId) + "]";
    }
  }

  /** Request payload was malformed or violated WebAuthn structural rules. */
  record InvalidPayload(String detail) implements RegistrationResult {
    public InvalidPayload {
      Objects.requireNonNull(detail, "detail");
    }
  }
}
