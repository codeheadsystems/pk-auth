// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.util.Objects;

/**
 * Sealed sum of outcomes from {@link RefreshTokenService#rotate(String)}. Adapters typically
 * pattern-match on this and translate to an HTTP response:
 *
 * <ul>
 *   <li>{@link Success} → {@code 200 OK} with the new wire token + access JWT
 *   <li>{@link Replayed}, {@link Expired}, {@link Unknown}, {@link Revoked} → {@code 401
 *       Unauthorized} with a typed {@code detail} field naming the variant
 * </ul>
 *
 * @since 1.1.0
 */
public sealed interface RotateResult {

  /**
   * The presented token was fresh; a successor has been minted in the same family. The consumer
   * issues a fresh access JWT from {@link #claimsForAccessIssue()} and returns {@link #pair()} to
   * the client.
   */
  record Success(RefreshTokenPair pair, RotatedClaims claimsForAccessIssue)
      implements RotateResult {
    public Success {
      Objects.requireNonNull(pair, "pair");
      Objects.requireNonNull(claimsForAccessIssue, "claimsForAccessIssue");
    }
  }

  /**
   * A used-or-revoked token from a known family was presented. The entire family has been scorched
   * ({@link RevokeReason#ROTATION_REPLAY}); the bearer must re-authenticate. The legitimate user
   * sees the next refresh fail and is redirected to the login page; that is the expected
   * operational signal.
   */
  record Replayed(String familyId, UserHandle userHandle) implements RotateResult {
    public Replayed {
      Objects.requireNonNull(familyId, "familyId");
      Objects.requireNonNull(userHandle, "userHandle");
    }
  }

  /** The token's {@code expiresAt} has passed. No family revocation. */
  record Expired() implements RotateResult {}

  /**
   * The presented {@code refreshId} did not match any persisted row: either the token was never
   * issued by this RP, was issued long enough ago that the row has been cleaned up, or the wire
   * format is malformed. No state changes.
   */
  record Unknown() implements RotateResult {}

  /**
   * The token belongs to a family that has already been revoked (logout, admin action, device
   * revoke, user delete, or a prior replay). The {@code reason} carries why.
   */
  record Revoked(RevokeReason reason) implements RotateResult {
    public Revoked {
      Objects.requireNonNull(reason, "reason");
    }
  }
}
