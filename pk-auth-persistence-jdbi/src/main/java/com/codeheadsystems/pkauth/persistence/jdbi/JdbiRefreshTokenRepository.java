// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.refresh.RefreshTokenRecord;
import com.codeheadsystems.pkauth.refresh.RevokeReason;
import com.codeheadsystems.pkauth.refresh.spi.RefreshTokenRepository;
import com.codeheadsystems.pkauth.spi.PkAuthPersistenceException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.JdbiException;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.Update;
import org.jspecify.annotations.Nullable;

/**
 * {@link RefreshTokenRepository} backed by the {@code refresh_tokens} table (Flyway V9; the {@code
 * amr} column added in V10). The load-bearing {@link #rotateAtomically} uses a JDBI transaction
 * that wraps a conditional {@code UPDATE} on the parent + an {@code INSERT} for the successor — see
 * ADR 0013.
 *
 * @since 1.1.0
 */
public final class JdbiRefreshTokenRepository implements RefreshTokenRepository {

  private final Jdbi jdbi;

  public JdbiRefreshTokenRepository(Jdbi jdbi) {
    this.jdbi = Objects.requireNonNull(jdbi, "jdbi");
  }

  @Override
  public void create(RefreshTokenRecord record) {
    wrap(
        "refresh_tokens.create",
        () -> {
          jdbi.useHandle(h -> insert(h, record));
          return null;
        });
  }

  @Override
  public Optional<RefreshTokenRecord> findByRefreshId(String refreshId) {
    return wrap(
        "refresh_tokens.findByRefreshId",
        () ->
            jdbi.withHandle(
                h ->
                    h.createQuery("SELECT * FROM refresh_tokens WHERE refresh_id = :id")
                        .bind("id", refreshId)
                        .map(MAPPER)
                        .findFirst()));
  }

  @Override
  public boolean rotateAtomically(
      String parentRefreshId, Instant now, RefreshTokenRecord successor) {
    Objects.requireNonNull(parentRefreshId, "parentRefreshId");
    Objects.requireNonNull(now, "now");
    Objects.requireNonNull(successor, "successor");
    return wrap(
        "refresh_tokens.rotateAtomically",
        () ->
            jdbi.inTransaction(
                h -> {
                  // Single atomic UPDATE on the parent. Predicate-equivalent to the canonical
                  // motif statement: only mark used iff fresh, exposed-row-count == 1 means we
                  // won the race against any concurrent rotator.
                  int marked =
                      h.createUpdate(
                              "UPDATE refresh_tokens SET used_at = :now"
                                  + " WHERE refresh_id = :id"
                                  + "   AND used_at IS NULL"
                                  + "   AND revoked_at IS NULL"
                                  + "   AND expires_at > :now")
                          .bind("now", OffsetDateTime.ofInstant(now, ZoneOffset.UTC))
                          .bind("id", parentRefreshId)
                          .execute();
                  if (marked == 0) {
                    return false;
                  }
                  insert(h, successor);
                  return true;
                }));
  }

  @Override
  public int revokeFamily(String familyId, Instant now, RevokeReason reason) {
    return wrap(
        "refresh_tokens.revokeFamily",
        () ->
            jdbi.withHandle(
                h ->
                    h.createUpdate(
                            "UPDATE refresh_tokens"
                                + "   SET revoked_at = :now, revoked_reason = :reason"
                                + " WHERE family_id = :fam AND revoked_at IS NULL")
                        .bind("now", OffsetDateTime.ofInstant(now, ZoneOffset.UTC))
                        .bind("reason", reason.name())
                        .bind("fam", familyId)
                        .execute()));
  }

  @Override
  public int revokeAllForUser(UserHandle userHandle, Instant now, RevokeReason reason) {
    return wrap(
        "refresh_tokens.revokeAllForUser",
        () ->
            jdbi.withHandle(
                h ->
                    h.createUpdate(
                            "UPDATE refresh_tokens"
                                + "   SET revoked_at = :now, revoked_reason = :reason"
                                + " WHERE user_handle = :uh AND revoked_at IS NULL")
                        .bind("now", OffsetDateTime.ofInstant(now, ZoneOffset.UTC))
                        .bind("reason", reason.name())
                        .bind("uh", userHandle.value())
                        .execute()));
  }

  @Override
  public List<RefreshTokenRecord> findByUserHandle(UserHandle userHandle) {
    return wrap(
        "refresh_tokens.findByUserHandle",
        () ->
            jdbi.withHandle(
                h ->
                    h.createQuery(
                            "SELECT * FROM refresh_tokens WHERE user_handle = :uh"
                                + " ORDER BY issued_at")
                        .bind("uh", userHandle.value())
                        .map(MAPPER)
                        .list()));
  }

  @Override
  public List<RefreshTokenRecord> findByFamilyId(String familyId) {
    return wrap(
        "refresh_tokens.findByFamilyId",
        () ->
            jdbi.withHandle(
                h ->
                    h.createQuery(
                            "SELECT * FROM refresh_tokens WHERE family_id = :fam"
                                + " ORDER BY issued_at")
                        .bind("fam", familyId)
                        .map(MAPPER)
                        .list()));
  }

  @Override
  public int deleteExpiredBefore(Instant cutoff) {
    return wrap(
        "refresh_tokens.deleteExpiredBefore",
        () ->
            jdbi.withHandle(
                h ->
                    h.createUpdate(
                            "DELETE FROM refresh_tokens"
                                + " WHERE expires_at < :cutoff"
                                + "   AND ((used_at IS NOT NULL AND used_at < :cutoff)"
                                + "        OR (revoked_at IS NOT NULL AND revoked_at < :cutoff))")
                        .bind("cutoff", OffsetDateTime.ofInstant(cutoff, ZoneOffset.UTC))
                        .execute()));
  }

  // -- Internals --------------------------------------------------------------------------

  private static void insert(Handle h, RefreshTokenRecord r) {
    try (Update update =
        h.createUpdate(
                "INSERT INTO refresh_tokens"
                    + " (refresh_id, token_hash, user_handle, audience, device_id, family_id,"
                    + "  parent_refresh_id, issued_at, expires_at, used_at, revoked_at,"
                    + "  revoked_reason, amr)"
                    + " VALUES (:rid, :hash, :uh, :aud, :did, :fam, :pid, :iat, :exp, :uat, :rat,"
                    + "  :reason, :amr)")
            .bind("rid", r.refreshId())
            .bind("hash", r.tokenHash())
            .bind("uh", r.userHandle().value())
            .bind("aud", r.audience())
            .bind("did", r.deviceId().orElse(null))
            .bind("fam", r.familyId())
            .bind("pid", r.parentRefreshId().orElse(null))
            .bind("iat", OffsetDateTime.ofInstant(r.issuedAt(), ZoneOffset.UTC))
            .bind("exp", OffsetDateTime.ofInstant(r.expiresAt(), ZoneOffset.UTC))
            .bind("reason", r.revokedReason().map(Enum::name).orElse(null))
            .bind("amr", joinAmr(r.amr()))) {
      // used_at and revoked_at are TIMESTAMPTZ; JDBI's untyped-null default (Types.VARCHAR) is
      // rejected by Postgres against a TIMESTAMPTZ column. Force Types.TIMESTAMP_WITH_TIMEZONE on
      // the null branch.
      bindNullable(
          update,
          "uat",
          r.usedAt().map(t -> OffsetDateTime.ofInstant(t, ZoneOffset.UTC)).orElse(null),
          Types.TIMESTAMP_WITH_TIMEZONE);
      bindNullable(
          update,
          "rat",
          r.revokedAt().map(t -> OffsetDateTime.ofInstant(t, ZoneOffset.UTC)).orElse(null),
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

  private static <T> T wrap(String op, Supplier<T> body) {
    try {
      return body.get();
    } catch (PkAuthPersistenceException already) {
      throw already;
    } catch (JdbiException e) {
      throw new PkAuthPersistenceException(op, e.getMessage(), e);
    }
  }

  private static final RowMapper<RefreshTokenRecord> MAPPER = (rs, ctx) -> readRow(rs);

  private static RefreshTokenRecord readRow(ResultSet rs) throws SQLException {
    OffsetDateTime usedAt = rs.getObject("used_at", OffsetDateTime.class);
    OffsetDateTime revokedAt = rs.getObject("revoked_at", OffsetDateTime.class);
    String revokedReasonStr = rs.getString("revoked_reason");
    String deviceId = rs.getString("device_id");
    String parentRefreshId = rs.getString("parent_refresh_id");
    return new RefreshTokenRecord(
        rs.getString("refresh_id"),
        rs.getBytes("token_hash"),
        UserHandle.of(rs.getBytes("user_handle")),
        rs.getString("audience"),
        Optional.ofNullable(deviceId),
        rs.getString("family_id"),
        Optional.ofNullable(parentRefreshId),
        rs.getObject("issued_at", OffsetDateTime.class).toInstant(),
        rs.getObject("expires_at", OffsetDateTime.class).toInstant(),
        Optional.ofNullable(usedAt).map(OffsetDateTime::toInstant),
        Optional.ofNullable(revokedAt).map(OffsetDateTime::toInstant),
        Optional.ofNullable(revokedReasonStr).map(RevokeReason::valueOf),
        splitAmr(rs.getString("amr")));
  }

  /** Serializes the RFC 8176 {@code amr} references as a comma-separated string for storage. */
  private static String joinAmr(List<String> amr) {
    return String.join(",", amr);
  }

  /**
   * Parses the stored comma-separated {@code amr} string back into a list. A null/blank value (rows
   * written before the V10 column existed) maps to the generic {@code ["user"]}.
   */
  private static List<String> splitAmr(String stored) {
    if (stored == null || stored.isBlank()) {
      return List.of("user");
    }
    return List.of(stored.split(","));
  }
}
