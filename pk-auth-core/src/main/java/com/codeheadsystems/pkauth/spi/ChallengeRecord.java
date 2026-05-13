// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * In-flight WebAuthn challenge persisted between the start and finish of a ceremony.
 *
 * @param challenge the random challenge bytes the server issued to the client
 * @param purpose whether this challenge belongs to a registration or assertion ceremony
 * @param userHandle the user this challenge is bound to; nullable for usernameless flows where the
 *     user is only known at finish
 * @param expiresAt absolute expiration; consumers should treat past-due records as missing
 */
public record ChallengeRecord(
    byte[] challenge, Purpose purpose, @Nullable UserHandle userHandle, Instant expiresAt) {

  public ChallengeRecord {
    Objects.requireNonNull(challenge, "challenge");
    if (challenge.length == 0) {
      throw new IllegalArgumentException("challenge must be non-empty");
    }
    Objects.requireNonNull(purpose, "purpose");
    Objects.requireNonNull(expiresAt, "expiresAt");
    challenge = challenge.clone();
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
        && this.expiresAt.equals(other.expiresAt);
  }

  @Override
  public int hashCode() {
    return Objects.hash(Arrays.hashCode(challenge), purpose, userHandle, expiresAt);
  }

  /** Which ceremony issued this challenge. */
  public enum Purpose {
    REGISTRATION,
    ASSERTION
  }
}
