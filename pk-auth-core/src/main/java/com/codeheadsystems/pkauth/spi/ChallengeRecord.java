// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.api.UserVerificationRequirement;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * In-flight WebAuthn challenge persisted between the start and finish of a ceremony.
 *
 * @param challenge the random challenge bytes the server issued to the client
 * @param purpose whether this challenge belongs to a registration or authentication ceremony
 * @param userHandle the user this challenge is bound to; nullable for usernameless flows where the
 *     user is only known at finish
 * @param userVerification the user-verification requirement resolved at start (the per-request
 *     override if the caller supplied one, otherwise the ceremony default); persisted so the finish
 *     step can enforce it server-side rather than letting a per-request {@code REQUIRED} be
 *     silently downgraded. {@code null} means "no resolved requirement recorded" (legacy records /
 *     direct constructions), in which case the finish step enforces only the global ceremony
 *     config.
 * @param expiresAt absolute expiration; consumers should treat past-due records as missing
 * @since 0.9.0
 */
public record ChallengeRecord(
    byte[] challenge,
    Purpose purpose,
    @Nullable UserHandle userHandle,
    @Nullable UserVerificationRequirement userVerification,
    Instant expiresAt) {

  public ChallengeRecord {
    Objects.requireNonNull(challenge, "challenge");
    if (challenge.length == 0) {
      throw new IllegalArgumentException("challenge must be non-empty");
    }
    Objects.requireNonNull(purpose, "purpose");
    Objects.requireNonNull(expiresAt, "expiresAt");
    challenge = challenge.clone();
  }

  /**
   * Back-compatible constructor for callers that don't carry a resolved user-verification
   * requirement; equivalent to passing {@code null} for {@code userVerification}.
   *
   * @since 2.1.0
   */
  public ChallengeRecord(
      byte[] challenge, Purpose purpose, @Nullable UserHandle userHandle, Instant expiresAt) {
    this(challenge, purpose, userHandle, null, expiresAt);
  }

  @Override
  public byte[] challenge() {
    return challenge.clone();
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof ChallengeRecord other
        && Arrays.equals(this.challenge, other.challenge)
        && this.purpose == other.purpose
        && Objects.equals(this.userHandle, other.userHandle)
        && this.userVerification == other.userVerification
        && this.expiresAt.equals(other.expiresAt);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        Arrays.hashCode(challenge), purpose, userHandle, userVerification, expiresAt);
  }

  /**
   * Which ceremony issued this challenge. Host-facing vocabulary matches the {@code
   * /auth/authentication/*} URL family rather than WebAuthn's internal "assertion" wording.
   *
   * @since 0.9.1 — renamed from {@code ASSERTION}; pre-1.0 break with no deprecation.
   */
  public enum Purpose {
    REGISTRATION,
    AUTHENTICATION
  }
}
