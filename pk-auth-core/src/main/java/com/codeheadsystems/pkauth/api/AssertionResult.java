// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import java.util.Objects;

/**
 * Closed sum of outcomes from {@code PasskeyAuthenticationService.finishAuthentication}. Mapped to
 * HTTP responses by adapter modules.
 *
 * @since 0.9.0
 */
public sealed interface AssertionResult {

  /**
   * Whether the assertion counter advanced normally or was accepted despite regression (WARN
   * policy).
   */
  enum CounterStatus {
    /** Counter advanced as expected — no anomaly detected. */
    OK,
    /**
     * Counter regressed but was accepted because {@code CounterRegressionPolicy.WARN} is active.
     * Operators should alert on this status; the stored counter was NOT advanced.
     */
    REGRESSED_WARN
  }

  /**
   * Assertion succeeded; the credential's sign count and lastUsedAt should be updated.
   *
   * <p>Check {@link #counterStatus()} to distinguish a clean success from one accepted despite
   * counter regression under WARN policy. Callers MUST supply {@code counterStatus} explicitly —
   * the prior convenience constructor that defaulted to {@link CounterStatus#OK} was removed in
   * 0.9.1 to force the counter-status decision to be visible at every call site.
   *
   * <p>The {@code credentialId} component is the type-safe {@link CredentialId} value class (was
   * raw {@code byte[]} prior to 0.9.1). Adapter mappers and JWT helpers consume the value class
   * directly; wire JSON is unchanged because {@link CredentialId} has a registered Jackson
   * (de)serializer that emits base64url.
   *
   * @since 0.9.1
   */
  record Success(
      UserHandle userHandle, CredentialId credentialId, long signCount, CounterStatus counterStatus)
      implements AssertionResult {
    public Success {
      Objects.requireNonNull(userHandle, "userHandle");
      Objects.requireNonNull(credentialId, "credentialId");
      Objects.requireNonNull(counterStatus, "counterStatus");
      if (signCount < 0) {
        throw new IllegalArgumentException("signCount must be non-negative");
      }
    }
  }

  /**
   * The asserted credential id is not in the repository.
   *
   * <p>The {@code credentialId} component is the type-safe {@link CredentialId} value class (was
   * raw {@code byte[]} prior to 0.9.1).
   *
   * @since 0.9.1
   */
  record UnknownCredential(CredentialId credentialId) implements AssertionResult {
    public UnknownCredential {
      Objects.requireNonNull(credentialId, "credentialId");
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

  /**
   * Received counter is less than or equal to the stored counter — authenticator cloning risk.
   *
   * <p><b>No compact constructor:</b> this record intentionally accepts any pair of {@code long}
   * values, including negatives, equal values, and {@code received > stored}. The variant is
   * constructed at exactly one site ({@code
   * DefaultPasskeyAuthenticationService.handleCounterRegression}) where the inputs are already
   * validated against the authenticator-supplied sign count and the stored credential row; an extra
   * compact-ctor invariant here would only hide a bug at the construction site, not catch one at
   * the boundary. Treat {@code stored} and {@code received} as informational telemetry fields, not
   * as enforced contracts.
   *
   * @since 0.9.1
   */
  record CounterRegression(long stored, long received) implements AssertionResult {}

  /** Ceremony required user verification but the authenticator did not assert UV. */
  record UserVerificationRequired() implements AssertionResult {}

  /** WebAuthn signature failed cryptographic validation. */
  record InvalidSignature() implements AssertionResult {}

  /**
   * Ceremony was refused by the configured rate limiter before the signature was verified. Returned
   * by {@code finishAuthentication} when the per-IP budget for the configured window has been
   * exhausted.
   *
   * @param bucket which limiter bucket denied the call ({@code "ip"} or {@code "username"}) — kept
   *     for adapter logging / diagnostics; clients receive the response without this field
   * @since 0.9.1
   */
  record RateLimited(String bucket) implements AssertionResult {
    public RateLimited {
      Objects.requireNonNull(bucket, "bucket");
    }
  }
}
