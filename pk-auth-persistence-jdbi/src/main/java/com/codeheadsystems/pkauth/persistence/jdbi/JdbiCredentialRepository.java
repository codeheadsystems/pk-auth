// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.Transport;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.DuplicateCredentialException;
import com.codeheadsystems.pkauth.spi.PkAuthPersistenceException;
import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
// Array import kept for the row-mapper path that reads back the text[] column.
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.JdbiException;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.Update;
import org.jspecify.annotations.Nullable;

/**
 * {@link CredentialRepository} backed by the Phase 5 {@code credentials} table.
 *
 * <p>{@link #delete(UserHandle, CredentialId)} is a hard delete (since V7): the row is removed
 * outright. Audit history is the responsibility of the service layer's structured log pipeline
 * ({@code pkauth.credential.deleted} event emitted by {@code DefaultAdminService}); this repository
 * no longer writes to {@code pkauth_audit_events} for credential deletions.
 *
 * @since 0.9.1
 */
public final class JdbiCredentialRepository implements CredentialRepository {

  private final Jdbi jdbi;

  public JdbiCredentialRepository(Jdbi jdbi) {
    this.jdbi = Objects.requireNonNull(jdbi, "jdbi");
  }

  @Override
  public void save(CredentialRecord record) {
    String[] transportWire = new String[record.transports().size()];
    int i = 0;
    for (Transport t : record.transports()) {
      transportWire[i++] = t.wireName();
    }
    int inserted =
        wrap(
            "credentials.save",
            () ->
                jdbi.withHandle(
                    h -> {
                      Update update =
                          h.createUpdate(
                                  "INSERT INTO credentials (credential_id, user_handle,"
                                      + " public_key_cose, sign_count, label, aaguid, transports,"
                                      + " backup_eligible, backup_state, created_at, last_used_at)"
                                      + " VALUES (:cid, :uh, :pk, :sc, :label, :aaguid,"
                                      + " :transports, :be, :bs, :createdAt, :lastUsedAt)"
                                      + " ON CONFLICT (credential_id) DO NOTHING")
                              .bind("cid", record.credentialId().value())
                              .bind("uh", record.userHandle().value())
                              .bind("pk", record.publicKeyCose())
                              .bind("sc", record.signCount())
                              .bind("label", record.label())
                              .bindArray("transports", String.class, (Object[]) transportWire)
                              .bind("be", record.backupEligible())
                              .bind("bs", record.backupState())
                              .bind(
                                  "createdAt",
                                  OffsetDateTime.ofInstant(record.createdAt(), ZoneOffset.UTC));
                      // aaguid is null for platform authenticators / attestation=none. The default
                      // untyped-null binding uses Types.VARCHAR, which Postgres rejects against a
                      // UUID column ("column ... is of type uuid but expression is of type
                      // character varying"). Force Types.OTHER for the null case.
                      bindNullable(update, "aaguid", record.aaguid(), Types.OTHER);
                      bindNullable(
                          update,
                          "lastUsedAt",
                          record.lastUsedAt() == null
                              ? null
                              : OffsetDateTime.ofInstant(record.lastUsedAt(), ZoneOffset.UTC),
                          Types.TIMESTAMP_WITH_TIMEZONE);
                      return update.execute();
                    }));
    if (inserted == 0) {
      throw new DuplicateCredentialException(
          "Duplicate credential id; refusing to overwrite an existing credential");
    }
  }

  @Override
  public Optional<CredentialRecord> findByCredentialId(CredentialId credentialId) {
    return wrap(
        "credentials.findByCredentialId",
        () ->
            jdbi.withHandle(
                h ->
                    h.createQuery("SELECT * FROM credentials WHERE credential_id = :cid")
                        .bind("cid", credentialId.value())
                        .map(MAPPER)
                        .findFirst()));
  }

  @Override
  public List<CredentialRecord> findByUserHandle(UserHandle userHandle) {
    return wrap(
        "credentials.findByUserHandle",
        () ->
            jdbi.withHandle(
                h ->
                    h.createQuery(
                            "SELECT * FROM credentials"
                                + " WHERE user_handle = :uh"
                                + " ORDER BY created_at")
                        .bind("uh", userHandle.value())
                        .map(MAPPER)
                        .list()));
  }

  @Override
  public void updateSignCount(CredentialId credentialId, long newCount, Instant lastUsedAt) {
    // Guard against concurrent racing assertions overwriting a higher stored counter with a
    // lower one — that would silently defeat WebAuthn's clone-detection invariant. Only advance
    // the counter when the new value strictly exceeds the stored one.
    wrap(
        "credentials.updateSignCount",
        () -> {
          jdbi.useHandle(
              h ->
                  h.createUpdate(
                          "UPDATE credentials SET sign_count = :sc, last_used_at = :lua"
                              + " WHERE credential_id = :cid AND sign_count < :sc")
                      .bind("sc", newCount)
                      .bind("lua", OffsetDateTime.ofInstant(lastUsedAt, ZoneOffset.UTC))
                      .bind("cid", credentialId.value())
                      .execute());
          return null;
        });
  }

  @Override
  public void updateLabel(UserHandle userHandle, CredentialId credentialId, String label) {
    wrap(
        "credentials.updateLabel",
        () -> {
          jdbi.useHandle(
              h ->
                  h.createUpdate(
                          "UPDATE credentials SET label = :label"
                              + " WHERE credential_id = :cid AND user_handle = :uh")
                      .bind("label", label)
                      .bind("cid", credentialId.value())
                      .bind("uh", userHandle.value())
                      .execute());
          return null;
        });
  }

  /**
   * Hard-deletes the credential row. Audit history is the service layer's responsibility — {@code
   * DefaultAdminService.deleteCredential} emits a {@code pkauth.credential.deleted} structured log
   * event around this call.
   */
  @Override
  public void delete(UserHandle userHandle, CredentialId credentialId) {
    byte[] credIdBytes = credentialId.value();
    wrap(
        "credentials.delete",
        () -> {
          jdbi.useHandle(
              h ->
                  h.createUpdate(
                          "DELETE FROM credentials WHERE credential_id = :cid AND user_handle = :uh")
                      .bind("cid", credIdBytes)
                      .bind("uh", userHandle.value())
                      .execute());
          return null;
        });
  }

  @Override
  public int deleteByUserHandle(UserHandle userHandle) {
    return wrap(
        "credentials.deleteByUserHandle",
        () ->
            jdbi.withHandle(
                h ->
                    h.createUpdate("DELETE FROM credentials WHERE user_handle = :uh")
                        .bind("uh", userHandle.value())
                        .execute()));
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  /**
   * Binds a nullable value. When non-null, defers to JDBI's standard binding. When null, calls
   * {@code bindNull} with the supplied SQL type so Postgres receives a typed NULL rather than the
   * untyped-null default (Types.VARCHAR), which strict typing rejects against UUID and TIMESTAMPTZ
   * columns. See bug report for the original {@code aaguid} failure mode.
   */
  private static void bindNullable(
      Update update, String name, @Nullable Object value, int sqlType) {
    if (value == null) {
      update.bindNull(name, sqlType);
    } else {
      update.bind(name, value);
    }
  }

  /**
   * Runs {@code body} and wraps any {@link JdbiException} (or other unchecked JDBC exception) in a
   * {@link PkAuthPersistenceException} so adapter exception mappers can produce a uniform 503.
   * {@link PkAuthPersistenceException} (including {@link DuplicateCredentialException}) is
   * re-thrown unchanged so the duplicate-credential branch reaches the caller intact.
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

  private static final RowMapper<CredentialRecord> MAPPER = (rs, ctx) -> readRow(rs);

  private static CredentialRecord readRow(ResultSet rs) throws SQLException {
    byte[] credentialId = rs.getBytes("credential_id");
    byte[] userHandle = rs.getBytes("user_handle");
    byte[] pk = rs.getBytes("public_key_cose");
    long sc = rs.getLong("sign_count");
    String label = rs.getString("label");
    UUID aaguid = (UUID) rs.getObject("aaguid");
    Set<Transport> transports = readTransports(rs, "transports");
    boolean be = rs.getBoolean("backup_eligible");
    boolean bs = rs.getBoolean("backup_state");
    Instant createdAt = rs.getObject("created_at", OffsetDateTime.class).toInstant();
    OffsetDateTime lua = rs.getObject("last_used_at", OffsetDateTime.class);
    return new CredentialRecord(
        CredentialId.of(credentialId),
        UserHandle.of(userHandle),
        pk,
        sc,
        label,
        aaguid,
        transports,
        be,
        bs,
        createdAt,
        lua == null ? null : lua.toInstant());
  }

  private static Set<Transport> readTransports(ResultSet rs, String column) throws SQLException {
    Array array = rs.getArray(column);
    if (array == null) {
      return EnumSet.noneOf(Transport.class);
    }
    Object raw = array.getArray();
    if (!(raw instanceof Object[] elements)) {
      return EnumSet.noneOf(Transport.class);
    }
    Set<Transport> out = EnumSet.noneOf(Transport.class);
    for (Object e : elements) {
      if (e != null) {
        Transport.fromWire(e.toString()).ifPresent(out::add);
      }
    }
    return out;
  }
}
