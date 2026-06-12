// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import java.util.List;
import java.util.Objects;

/**
 * One-time-view payload from {@code POST /auth/admin/backup-codes/regenerate}. The plaintext codes
 * are returned to the caller exactly once; pk-auth stores only Argon2id hashes server-side.
 *
 * @since 0.9.0
 */
public record BackupCodesGenerated(List<String> codes) {
  public BackupCodesGenerated {
    Objects.requireNonNull(codes, "codes");
    codes = List.copyOf(codes);
  }
}
