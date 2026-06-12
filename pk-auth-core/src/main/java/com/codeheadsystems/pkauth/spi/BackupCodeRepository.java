// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Persistent storage for backup-code hashes (brief §6.3). One row per issued code.
 *
 * @since 0.9.0
 */
public interface BackupCodeRepository {

  /** Stored representation of a single backup code. The plaintext is never persisted. */
  record StoredBackupCode(
      String codeId,
      UserHandle userHandle,
      String hashedCode,
      boolean consumed,
      Instant createdAt,
      @Nullable Instant consumedAt) {
    public StoredBackupCode {
      Objects.requireNonNull(codeId, "codeId");
      Objects.requireNonNull(userHandle, "userHandle");
      Objects.requireNonNull(hashedCode, "hashedCode");
      Objects.requireNonNull(createdAt, "createdAt");
    }
  }

  /** Inserts a freshly issued backup code. */
  void save(StoredBackupCode code);

  /** Lists every backup code for a user, consumed or not. */
  List<StoredBackupCode> findByUserHandle(UserHandle userHandle);

  /**
   * Atomically marks the supplied code id as consumed for the given user. The {@code userHandle} is
   * the partition under which the code lives; implementations use it to address the row directly
   * instead of scanning.
   *
   * <p>Implementations MUST guarantee single-use semantics: the guarded UPDATE (or conditional
   * write) must only succeed when an unconsumed row for {@code (userHandle, codeId)} exists.
   * Concurrent callers observing the same code as unconsumed must NOT both receive {@code true} —
   * exactly one must win. Return value:
   *
   * <ul>
   *   <li>{@code true} — this call atomically transitioned an unconsumed row to consumed and the
   *       caller is the unique winner. The caller may now mint a credential / JWT from this code.
   *   <li>{@code false} — the row does not exist, was already consumed, or a concurrent caller won
   *       the race. The caller MUST treat this as a verification miss.
   * </ul>
   *
   * @since 0.9.1
   */
  boolean consume(UserHandle userHandle, String codeId, Instant consumedAt);

  /** Deletes every backup code for a user — used by {@code regenerateBackupCodes}. */
  void deleteByUserHandle(UserHandle userHandle);

  /**
   * Atomically replaces all backup codes for a user: deletes every existing code and inserts the
   * supplied records in a single logical unit of work.
   *
   * <p>Implementations MUST execute the delete and the inserts as a single atomic operation. A
   * mid-operation failure must NOT leave the user with a partial or empty set of codes — readers
   * must observe either the original set or the new set in its entirety. Use a database transaction
   * (JDBI), {@code TransactWriteItems} (DynamoDB), or equivalent locking (in-memory).
   *
   * @param userHandle the user whose codes are being replaced; must be non-null
   * @param records the new set of codes (may be empty)
   * @since 0.9.1
   */
  void replaceAll(UserHandle userHandle, List<StoredBackupCode> records);
}
