// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;

/**
 * Persistent storage for SMS-OTP records (brief §6.5).
 *
 * @since 0.9.0
 */
public interface OtpRepository {

  /**
   * Persisted SMS-OTP row.
   *
   * @param otpId opaque server-generated id
   * @param userHandle owning user
   * @param phoneE164 destination phone in E.164 format
   * @param hashedCode HMAC-SHA256(pepper, code) encoded as Base64 of the dispatched code
   * @param attempts how many verification attempts have been made
   * @param maxAttempts threshold above which the code is locked
   * @param consumed whether the code has been verified successfully
   * @param createdAt issuance timestamp (used for rate limiting)
   * @param expiresAt absolute expiry; consumers must treat past-due records as invalid
   */
  record StoredOtp(
      String otpId,
      UserHandle userHandle,
      String phoneE164,
      String hashedCode,
      int attempts,
      int maxAttempts,
      boolean consumed,
      Instant createdAt,
      Instant expiresAt) {
    public StoredOtp {
      Objects.requireNonNull(otpId, "otpId");
      Objects.requireNonNull(userHandle, "userHandle");
      Objects.requireNonNull(phoneE164, "phoneE164");
      Objects.requireNonNull(hashedCode, "hashedCode");
      Objects.requireNonNull(createdAt, "createdAt");
      Objects.requireNonNull(expiresAt, "expiresAt");
      if (attempts < 0) {
        throw new IllegalArgumentException("attempts must be non-negative");
      }
      if (maxAttempts <= 0) {
        throw new IllegalArgumentException("maxAttempts must be positive");
      }
    }
  }

  /** Inserts a freshly issued OTP record. */
  void save(StoredOtp otp);

  /**
   * Returns the most recently issued, non-consumed, and non-expired ({@code expiresAt > now}) OTP
   * for the given user + phone, if any. Used by {@code OtpService.verify} as the candidate for
   * matching.
   *
   * @param userHandle owning user
   * @param phoneE164 destination phone in E.164 format
   * @param now the caller's current instant (from the host ClockProvider)
   * @since 2.2.0
   */
  Optional<StoredOtp> findLatestActive(UserHandle userHandle, String phoneE164, Instant now);

  /**
   * Atomically increments the attempts counter for the supplied OTP id and returns the new count.
   * Callers must reject the verification attempt if the returned count exceeds {@code maxAttempts}.
   * The {@code userHandle} addresses the row directly so implementations can avoid full-table
   * scans.
   *
   * <p>Returns {@link OptionalInt#empty()} when no row exists for the supplied {@code (userHandle,
   * otpId)} pair. Callers MUST treat the empty case as "no active OTP" — not as a zero-count
   * attempt — so that a phantom verify against a deleted / never-issued row cannot masquerade as a
   * successful low-attempt verification.
   *
   * @param userHandle owner of the OTP record
   * @param otpId the OTP record to increment
   * @return the attempts value <em>after</em> the increment, or {@link OptionalInt#empty()} if the
   *     row does not exist
   * @since 0.9.1
   */
  OptionalInt incrementAttempts(UserHandle userHandle, String otpId);

  /**
   * Atomically marks the supplied OTP id consumed for the given user, but only when it is not
   * already consumed. Returns {@code true} when this call performed the transition (a previously
   * unconsumed row is now consumed); {@code false} when the row is missing or was already consumed
   * by a concurrent caller. Implementations must enforce this guard server-side so two concurrent
   * verifies cannot both observe success.
   *
   * @param userHandle owner of the OTP record
   * @param otpId the OTP record to consume
   * @return {@code true} iff this call flipped the row from unconsumed to consumed
   * @since 0.9.1
   */
  boolean consume(UserHandle userHandle, String otpId);

  /**
   * Returns how many OTPs were issued for the supplied (user, phone) since {@code since}. Used by
   * the service for rate limiting (brief §6.5 — at most 3 per 15 minutes).
   */
  int countSince(UserHandle userHandle, String phoneE164, Instant since);

  /**
   * Deletes every OTP row owned by the supplied user. Called by {@link
   * com.codeheadsystems.pkauth.lifecycle.UserDeletionService} during user-deletion fan-out.
   *
   * <p>Returns the number of rows removed (best-effort; used for structured logging). Must be
   * idempotent — a call against a user with no remaining rows returns {@code 0}.
   *
   * @since 1.1.0
   */
  int deleteByUserHandle(UserHandle userHandle);
}
