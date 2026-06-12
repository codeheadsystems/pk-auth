// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import com.codeheadsystems.pkauth.api.UserHandle;

/**
 * Decides whether the JWT-authenticated {@code actor} is allowed to act on {@code target}'s
 * account. Default implementation is subject-scoped — a user only acts on themselves. Adapter
 * modules can plug in support-staff-impersonation flows by overriding this SPI.
 *
 * @since 0.9.0
 */
@FunctionalInterface
public interface AdminAuthorizer {

  boolean canAct(UserHandle actor, UserHandle target);

  /** The brief's default: actor must equal target. */
  static AdminAuthorizer subjectScoped() {
    return (actor, target) -> actor.equals(target);
  }
}
