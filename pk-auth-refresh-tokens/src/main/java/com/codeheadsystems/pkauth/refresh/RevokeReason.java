// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh;

/**
 * Categorical reason a refresh token (or an entire family) was revoked. Persisted on the row at
 * revoke time for forensic visibility and to disambiguate the {@link RotateResult.Revoked#reason()}
 * returned to a rotation attempt against an already-revoked family.
 *
 * @since 1.1.0
 */
public enum RevokeReason {

  /** User-driven logout. */
  LOGOUT,

  /**
   * A used or revoked token in this family was presented again; this is the load-bearing replay
   * defence outcome. The entire family is revoked and the bearer must re-authenticate.
   */
  ROTATION_REPLAY,

  /** A device the token was bound to was revoked. Reserved for future device-binding work. */
  DEVICE_REVOKED,

  /** The owning user was deleted; revocation runs as part of the user-deletion fan-out. */
  USER_DELETED,

  /** Manual admin action (incident response, password reset, security event). */
  ADMIN
}
