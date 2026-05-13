// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Closed sum of outcomes from {@code PasskeyAuthenticationService.finishAuthentication}. Mapped to
 * HTTP responses by adapter modules.
 */
public sealed interface AssertionResult {

  /** Assertion succeeded; the credential's sign count and lastUsedAt should be updated. */
  record Success(UserHandle userHandle, byte[] credentialId, long signCount)
      implements AssertionResult {
    public Success {
      Objects.requireNonNull(userHandle, "userHandle");
      Objects.requireNonNull(credentialId, "credentialId");
      if (signCount < 0) {
        throw new IllegalArgumentException("signCount must be non-negative");
      }
      credentialId = credentialId.clone();
    }

    @Override
    public byte[] credentialId() {
      return credentialId.clone();
    }

    @Override
    public boolean equals(Object o) {
      return o instanceof Success other
          && this.userHandle.equals(other.userHandle)
          && Arrays.equals(this.credentialId, other.credentialId)
          && this.signCount == other.signCount;
    }

    @Override
    public int hashCode() {
      return Objects.hash(userHandle, Arrays.hashCode(credentialId), signCount);
    }

    @Override
    public String toString() {
      return "Success[userHandle="
          + userHandle
          + ", credentialId="
          + HexFormat.of().formatHex(credentialId)
          + ", signCount="
          + signCount
          + "]";
    }
  }

  /** The asserted credential id is not in the repository. */
  record UnknownCredential(byte[] credentialId) implements AssertionResult {
    public UnknownCredential {
      Objects.requireNonNull(credentialId, "credentialId");
      credentialId = credentialId.clone();
    }

    @Override
    public byte[] credentialId() {
      return credentialId.clone();
    }

    @Override
    public boolean equals(Object o) {
      return o instanceof UnknownCredential other
          && Arrays.equals(this.credentialId, other.credentialId);
    }

    @Override
    public int hashCode() {
      return Arrays.hashCode(credentialId);
    }

    @Override
    public String toString() {
      return "UnknownCredential[credentialId=" + HexFormat.of().formatHex(credentialId) + "]";
    }
  }

  /** Challenge missing, expired, or mismatched against the stored challenge. */
  record InvalidChallenge(String detail) implements AssertionResult {
    public InvalidChallenge {
      Objects.requireNonNull(detail, "detail");
    }
  }

  /** Client-reported origin did not match an allowed origin from {@code RelyingPartyConfig}. */
  record OriginMismatch(String expected, String actual) implements AssertionResult {
    public OriginMismatch {
      Objects.requireNonNull(expected, "expected");
      Objects.requireNonNull(actual, "actual");
    }
  }

  /** Received counter is less than or equal to the stored counter — authenticator cloning risk. */
  record CounterRegression(long stored, long received) implements AssertionResult {}

  /** Ceremony required user verification but the authenticator did not assert UV. */
  record UserVerificationRequired() implements AssertionResult {}

  /** WebAuthn signature failed cryptographic validation. */
  record InvalidSignature() implements AssertionResult {}
}
