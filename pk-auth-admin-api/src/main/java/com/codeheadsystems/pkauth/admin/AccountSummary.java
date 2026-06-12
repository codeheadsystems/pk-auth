// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.util.Objects;

/**
 * Wire-shape returned by {@code GET /auth/admin/account}.
 *
 * @since 0.9.0
 */
public record AccountSummary(
    UserHandle userHandle,
    String username,
    String displayName,
    boolean emailVerified,
    boolean phoneVerified,
    int credentialCount,
    int remainingBackupCodes) {

  public AccountSummary {
    Objects.requireNonNull(userHandle, "userHandle");
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(displayName, "displayName");
  }
}
