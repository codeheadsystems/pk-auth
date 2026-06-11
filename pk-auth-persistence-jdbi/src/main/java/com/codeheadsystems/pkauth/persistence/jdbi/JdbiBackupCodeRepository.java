// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.PkAuthPersistenceException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.JdbiException;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.Update;
import org.jspecify.annotations.Nullable;

/**
 * {@link BackupCodeRepository} backed by the {@code backup_codes} table (Flyway V3).
 *
 * <p>Since V6, backup codes are soft-deleted: consumed codes have {@code revoked_at} set rather
 * than being removed. Failed verification attempts write an audit-event row to {@code
 * pkauth_audit_events}. All active-row queries filter on {@code revoked_at IS NULL}.
 */
public final class JdbiBackupCodeRepository implements BackupCodeRepository {

  private final Jdbi jdbi;

  public JdbiBackupCodeRepository(Jdbi jdbi) {
    this.jdbi = Objects.requireNonNull(jdbi, "jdbi");
  }

  @Override
  public void save(StoredBackupCode code) {
    wrap(
        "backupCodes.save",
        () -> {
          jdbi.useHandle(h -> insertBackupCode(h, code));
          return null;
        });
  }

  private static void insertBackupCode(Handle h, StoredBackupCode code) {
    try (Update update =
        h.createUpdate(
                "INSERT INTO backup_codes (code_id, user_handle, hashed_code, consumed,"
                    + " consumed_at, created_at)"
                    + " VALUES (:cid, :uh, :hash, :consumed, :consumedAt, :createdAt)")
            .bind("cid", code.codeId())
            .bind("uh", code.userHandle().value())
            .bind("hash", code.hashedCode())
            .bind("consumed", code.consumed())
            .bind("createdAt", OffsetDateTime.ofInstant(code.createdAt(), ZoneOffset.UTC))) {
      // consumed_at is TIMESTAMPTZ; force Types.TIMESTAMP_WITH_TIMEZONE on the null branch so PG
      // does not reject the untyped-null (Types.VARCHAR) default.
      bindNullable(
          update,
          "consumedAt",
          code.consumedAt() == null
              ? null
              : OffsetDateTime.ofInstant(code.consumedAt(), ZoneOffset.UTC),
          Types.TIMESTAMP_WITH_TIMEZONE);
      update.execute();
    }
  }

  private static void bindNullable(
      Update update, String name, @Nullable Object value, int sqlType) {
    if (value == null) {
      update.bindNull(name, sqlType);
    } else {
      update.bind(name, value);
    }
  }

  /** Returns only active (not yet revoked) codes for the given user handle. */
  @Override
  public List<StoredBackupCode> findByUserHandle(UserHandle userHandle) {
    return wrap(
        "backupCodes.findByUserHandle",
        () ->
            jdbi.withHandle(
                h ->
                    h.createQuery(
                            "SELECT * FROM backup_codes"
                                + " WHERE user_handle = :uh AND revoked_at IS NULL"
                                + " ORDER BY created_at")
                        .bind("uh", userHandle.value())
                        .map(MAPPER)
                        .list()));
  }

  /**
   * Marks the code as consumed via a soft-delete (sets {@code revoked_at} and {@code revoked_reason
   * = 'consumed'}) instead of removing the row. The UPDATE is guarded by {@code consumed = FALSE
   * AND revoked_at IS NULL} so concurrent callers cannot both succeed.
   *
   * @return {@code true} when the guarded UPDATE consumed an unconsumed row; {@code false} when the
   *     row was missing or already consumed (including the loser of a concurrent race).
   */
  @Override
  public boolean consume(UserHandle userHandle, String codeId, Instant consumedAt) {
    return wrap(
        "backupCodes.consume",
        () ->
            jdbi.withHandle(
                h ->
                    h.createUpdate(
                                "UPDATE backup_codes"
                                    + " SET consumed = TRUE, consumed_at = :consumedAt,"
                                    + "     revoked_at = :consumedAt, revoked_reason = 'consumed'"
                                    + " WHERE user_handle = :uh AND code_id = :cid"
                                    + "       AND consumed = FALSE AND revoked_at IS NULL")
                            .bind(
                                "consumedAt", OffsetDateTime.ofInstant(consumedAt, ZoneOffset.UTC))
                            .bind("uh", userHandle.value())
                            .bind("cid", codeId)
                            .execute()
                        > 0));
  }

  /**
   * Records a failed backup-code verification attempt in the audit log.
   *
   * @param codeId the code that was attempted (may be unknown)
   * @param userHandle the user whose code was attempted, or {@code null} if unknown
   */
  public void recordVerifyFailure(String codeId, UserHandle userHandle) {
    wrap(
        "backupCodes.recordVerifyFailure",
        () -> {
          insertAuditEvent(
              "backup_code_verify_failed",
              userHandle == null ? null : userHandle.value(),
              codeId,
              null);
          return null;
        });
  }

  /**
   * Soft-deletes all active codes for a user handle by setting {@code revoked_at = NOW()} and
   * {@code revoked_reason = 'bulk_delete'}.
   */
  @Override
  public void deleteByUserHandle(UserHandle userHandle) {
    wrap(
        "backupCodes.deleteByUserHandle",
        () -> {
          jdbi.useHandle(
              h ->
                  h.createUpdate(
                          "UPDATE backup_codes"
                              + " SET revoked_at = NOW(), revoked_reason = 'bulk_delete'"
                              + " WHERE user_handle = :uh AND revoked_at IS NULL")
                      .bind("uh", userHandle.value())
                      .execute());
          return null;
        });
  }

  /**
   * Atomically replaces all active codes for a user inside a single JDBI transaction: soft-deletes
   * existing rows and inserts the new set. A failure mid-insert rolls back the entire transaction
   * so the user is never left with a partial or empty code set.
   *
   * @since 0.9.1
   */
  @Override
  public void replaceAll(UserHandle userHandle, List<StoredBackupCode> records) {
    wrap(
        "backupCodes.replaceAll",
        () -> {
          jdbi.useTransaction(
              h -> {
                h.createUpdate(
                        "UPDATE backup_codes"
                            + " SET revoked_at = NOW(), revoked_reason = 'bulk_delete'"
                            + " WHERE user_handle = :uh AND revoked_at IS NULL")
                    .bind("uh", userHandle.value())
                    .execute();
                for (StoredBackupCode code : records) {
                  insertBackupCode(h, code);
                }
              });
          return null;
        });
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  /**
   * Runs {@code body} and wraps any {@link JdbiException} in a {@link PkAuthPersistenceException}
   * so adapter exception mappers can produce a uniform 503. Existing {@link
   * PkAuthPersistenceException} instances are re-thrown unchanged.
   */
  private static <T> T wrap(String op, Supplier<T> body) {
    try {
      return body.get();
    } catch (PkAuthPersistenceException already) {
      throw already;
    } catch (JdbiException e) {
      throw new PkAuthPersistenceException(op, e.getMessage(), e);
    }
  }

  private void insertAuditEvent(
      String eventType, byte[] userHandle, String subjectId, String detail) {
    jdbi.useHandle(
        h -> {
          Update update =
              h.createUpdate(
                      "INSERT INTO pkauth_audit_events"
                          + " (event_type, user_handle, subject_id, detail)"
                          + " VALUES (:eventType, :userHandle, :subjectId, :detail)")
                  .bind("eventType", eventType)
                  .bind("subjectId", subjectId)
                  .bind("detail", detail);
          // user_handle is BYTEA and nullable (unknown attacker). Untyped-null default
          // (Types.VARCHAR) is rejected against BYTEA — force Types.BINARY on the null branch.
          bindNullable(update, "userHandle", userHandle, Types.BINARY);
          update.execute();
        });
  }

  private static final RowMapper<StoredBackupCode> MAPPER = (rs, ctx) -> readRow(rs);

  private static StoredBackupCode readRow(ResultSet rs) throws SQLException {
    OffsetDateTime consumedAt = rs.getObject("consumed_at", OffsetDateTime.class);
    return new StoredBackupCode(
        rs.getString("code_id"),
        UserHandle.of(rs.getBytes("user_handle")),
        rs.getString("hashed_code"),
        rs.getBoolean("consumed"),
        rs.getObject("created_at", OffsetDateTime.class).toInstant(),
        consumedAt == null ? null : consumedAt.toInstant());
  }
}
