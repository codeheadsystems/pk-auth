// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

/**
 * Tunable safety rules. Defaults match brief §6.9 — the last-credential guard is on; deleting a
 * credential that would leave the user with zero credentials AND zero remaining backup codes is
 * rejected with a {@link AdminResult.Conflict}.
 *
 * @param allowDeleteWithoutBackupCodes when true, callers can delete the last credential even when
 *     no backup codes remain. The brief recommends keeping this {@code false}.
 * @since 0.9.0
 */
public record AdminSafetyConfig(boolean allowDeleteWithoutBackupCodes) {

  /** Default config: last-credential guard active. */
  public static AdminSafetyConfig defaults() {
    return new AdminSafetyConfig(false);
  }
}
