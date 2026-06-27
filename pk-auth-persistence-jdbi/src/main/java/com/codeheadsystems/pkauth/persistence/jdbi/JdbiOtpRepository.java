// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.mapper.RowMapper;

/** {@link OtpRepository} backed by the {@code otp_codes} table (Flyway V4). */
public final class JdbiOtpRepository implements OtpRepository {

  private final Jdbi jdbi;

  public JdbiOtpRepository(Jdbi jdbi) {
    this.jdbi = Objects.requireNonNull(jdbi, "jdbi");
  }

  @Override
  public void save(StoredOtp otp) {
    JdbiSupport.wrap(
        "otp.save",
        () -> {
          jdbi.useHandle(
              h ->
                  h.createUpdate(
                          "INSERT INTO otp_codes (otp_id, user_handle, phone_e164, hashed_code,"
                              + " attempts, max_attempts, consumed, expires_at, created_at)"
                              + " VALUES (:oid, :uh, :phone, :hash, :attempts, :max, :consumed,"
                              + " :expiresAt, :createdAt)")
                      .bind("oid", otp.otpId())
                      .bind("uh", otp.userHandle().value())
                      .bind("phone", otp.phoneE164())
                      .bind("hash", otp.hashedCode())
                      .bind("attempts", otp.attempts())
                      .bind("max", otp.maxAttempts())
                      .bind("consumed", otp.consumed())
                      .bind("expiresAt", OffsetDateTime.ofInstant(otp.expiresAt(), ZoneOffset.UTC))
                      .bind("createdAt", OffsetDateTime.ofInstant(otp.createdAt(), ZoneOffset.UTC))
                      .execute());
          return null;
        });
  }

  @Override
  public Optional<StoredOtp> findLatestActive(UserHandle userHandle, String phoneE164) {
    return JdbiSupport.wrap(
        "otp.findLatestActive",
        () ->
            jdbi.withHandle(
                h ->
                    h.createQuery(
                            // NOTE: expiry is intentionally NOT filtered here. This SPI method has
                            // no ClockProvider, so the only available "now" would be the database
                            // wall clock (NOW()), which is a second, uncontrollable clock source
                            // independent of the host's ClockProvider (it also breaks fixed-clock
                            // testing). OtpService.verify re-checks expiry against the host clock
                            // and
                            // returns Expired, so an expired row surfaced here is rejected there.
                            // Filtering expiry in-store would require threading ClockProvider
                            // through
                            // the OtpRepository SPI — deferred.
                            "SELECT * FROM otp_codes WHERE user_handle = :uh AND phone_e164 ="
                                + " :phone AND consumed = FALSE"
                                + " ORDER BY created_at DESC LIMIT 1")
                        .bind("uh", userHandle.value())
                        .bind("phone", phoneE164)
                        .map(MAPPER)
                        .findFirst()));
  }

  @Override
  public OptionalInt incrementAttempts(UserHandle userHandle, String otpId) {
    return JdbiSupport.wrap(
        "otp.incrementAttempts",
        () ->
            jdbi.withHandle(
                h -> {
                  // Increment unconditionally. A prior guarded `attempts < max_attempts` made the
                  // UPDATE a no-op once the cap was reached, which let callers loop verification
                  // forever within the TTL (the post-increment value never exceeded max_attempts,
                  // so the cap check in OtpService never tripped). Matches the DynamoDB impl,
                  // which also increments without a guard. Caller is required to compare the
                  // returned count against maxAttempts.
                  //
                  // Single statement via RETURNING so the post-increment value the caller sees is
                  // this transaction's own write — concurrent attempts get distinct counters and
                  // the cap check in OtpService can't be bypassed by an interleaved read.
                  Optional<Integer> current =
                      h.createQuery(
                              "UPDATE otp_codes SET attempts = attempts + 1"
                                  + " WHERE user_handle = :uh AND otp_id = :oid"
                                  + " RETURNING attempts")
                          .bind("uh", userHandle.value())
                          .bind("oid", otpId)
                          .mapTo(Integer.class)
                          .findFirst();
                  // SPI contract: empty signals "no such row".
                  return current.map(OptionalInt::of).orElse(OptionalInt.empty());
                }));
  }

  @Override
  public boolean consume(UserHandle userHandle, String otpId) {
    return JdbiSupport.wrap(
        "otp.consume",
        () ->
            jdbi.withHandle(
                h ->
                    h.createUpdate(
                                "UPDATE otp_codes SET consumed = TRUE"
                                    + " WHERE user_handle = :uh AND otp_id = :oid"
                                    + "       AND consumed = FALSE")
                            .bind("uh", userHandle.value())
                            .bind("oid", otpId)
                            .execute()
                        == 1));
  }

  @Override
  public int countSince(UserHandle userHandle, String phoneE164, Instant since) {
    return JdbiSupport.wrap(
        "otp.countSince",
        () ->
            jdbi.withHandle(
                h ->
                    h.createQuery(
                            "SELECT COUNT(*) FROM otp_codes WHERE user_handle = :uh AND phone_e164"
                                + " = :phone AND created_at >= :since")
                        .bind("uh", userHandle.value())
                        .bind("phone", phoneE164)
                        .bind("since", OffsetDateTime.ofInstant(since, ZoneOffset.UTC))
                        .mapTo(Integer.class)
                        .one()));
  }

  @Override
  public int deleteByUserHandle(UserHandle userHandle) {
    return JdbiSupport.wrap(
        "otp.deleteByUserHandle",
        () ->
            jdbi.withHandle(
                h ->
                    h.createUpdate("DELETE FROM otp_codes WHERE user_handle = :uh")
                        .bind("uh", userHandle.value())
                        .execute()));
  }

  private static final RowMapper<StoredOtp> MAPPER = (rs, ctx) -> readRow(rs);

  private static StoredOtp readRow(ResultSet rs) throws SQLException {
    return new StoredOtp(
        rs.getString("otp_id"),
        UserHandle.of(rs.getBytes("user_handle")),
        rs.getString("phone_e164"),
        rs.getString("hashed_code"),
        rs.getInt("attempts"),
        rs.getInt("max_attempts"),
        rs.getBoolean("consumed"),
        rs.getObject("created_at", OffsetDateTime.class).toInstant(),
        rs.getObject("expires_at", OffsetDateTime.class).toInstant());
  }
}
