// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

/**
 * Returned from {@code POST /auth/admin/phone/complete-verification}.
 *
 * @since 0.9.0
 */
public sealed interface PhoneVerificationResult {

  /** Code matched and the user's {@code phoneVerified} flag is now true. */
  record Verified() implements PhoneVerificationResult {}

  /** Code did not match the active OTP. */
  record Mismatch(int remainingAttempts) implements PhoneVerificationResult {}

  /** The active OTP has expired. */
  record Expired() implements PhoneVerificationResult {}

  /** Too many failed attempts; the user must request a new OTP. */
  record AttemptsExceeded() implements PhoneVerificationResult {}
}
