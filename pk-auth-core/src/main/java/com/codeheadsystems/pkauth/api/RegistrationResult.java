// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import com.codeheadsystems.pkauth.credential.AuthenticatorData;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import java.util.Objects;

/**
 * Closed sum of outcomes from {@code PasskeyAuthenticationService.finishRegistration}. Mapped to
 * HTTP responses by adapter modules.
 *
 * @since 0.9.0
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

  /**
   * A credential with the same id is already registered.
   *
   * <p>The {@code credentialId} component is the type-safe {@link CredentialId} value class (was
   * raw {@code byte[]} prior to 0.9.1).
   *
   * @since 0.9.1
   */
  record DuplicateCredential(CredentialId credentialId) implements RegistrationResult {
    public DuplicateCredential {
      Objects.requireNonNull(credentialId, "credentialId");
    }
  }

  /** Request payload was malformed or violated WebAuthn structural rules. */
  record InvalidPayload(String detail) implements RegistrationResult {
    public InvalidPayload {
      Objects.requireNonNull(detail, "detail");
    }
  }

  /**
   * Ceremony was refused by the configured rate limiter before the attestation was verified.
   * Returned by {@code finishRegistration} when the per-IP budget for the configured window has
   * been exhausted.
   *
   * @param bucket which limiter bucket denied the call ({@code "ip"} or {@code "username"}) — kept
   *     for adapter logging / diagnostics; clients receive the response without this field
   * @since 0.9.1
   */
  record RateLimited(String bucket) implements RegistrationResult {
    public RateLimited {
      Objects.requireNonNull(bucket, "bucket");
    }
  }
}
