// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.jwt.AccessTokenStore;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Optional;
import org.jdbi.v3.core.Jdbi;

/**
 * {@link AccessTokenStore} backed by the {@code access_tokens} table (Flyway V8). Inserts on issue,
 * lookups by jti on validate, deletes by jti / user / expiry on logout / cleanup.
 *
 * @since 1.1.0
 */
public final class JdbiAccessTokenStore implements AccessTokenStore {

  private final Jdbi jdbi;

  public JdbiAccessTokenStore(Jdbi jdbi) {
    this.jdbi = Objects.requireNonNull(jdbi, "jdbi");
  }

  @Override
  public void record(
      String jti,
      UserHandle userHandle,
      String audience,
      Optional<String> deviceId,
      Instant issuedAt,
      Instant expiresAt) {
    Objects.requireNonNull(jti, "jti");
    Objects.requireNonNull(userHandle, "userHandle");
    Objects.requireNonNull(audience, "audience");
    Objects.requireNonNull(deviceId, "deviceId");
    Objects.requireNonNull(issuedAt, "issuedAt");
    Objects.requireNonNull(expiresAt, "expiresAt");
    JdbiSupport.wrap(
        "access_tokens.record",
        () -> {
          // ON CONFLICT DO UPDATE so re-recording the same jti (e.g. an issuer retry after a
          // transient failure on the wire return) converges on the latest values rather than
          // throwing. UUID collisions are astronomically unlikely; the upsert is for retry
          // safety, not real duplicates.
          jdbi.useHandle(
              h ->
                  h.createUpdate(
                          "INSERT INTO access_tokens"
                              + " (jti, user_handle, audience, device_id, issued_at, expires_at)"
                              + " VALUES (:jti, :uh, :aud, :did, :iat, :exp)"
                              + " ON CONFLICT (jti) DO UPDATE SET"
                              + "   user_handle = EXCLUDED.user_handle,"
                              + "   audience = EXCLUDED.audience,"
                              + "   device_id = EXCLUDED.device_id,"
                              + "   issued_at = EXCLUDED.issued_at,"
                              + "   expires_at = EXCLUDED.expires_at")
                      .bind("jti", jti)
                      .bind("uh", userHandle.value())
                      .bind("aud", audience)
                      .bind("did", deviceId.orElse(null))
                      .bind("iat", OffsetDateTime.ofInstant(issuedAt, ZoneOffset.UTC))
                      .bind("exp", OffsetDateTime.ofInstant(expiresAt, ZoneOffset.UTC))
                      .execute());
          return null;
        });
  }

  @Override
  public boolean exists(String jti) {
    if (jti == null) {
      return false;
    }
    return JdbiSupport.wrap(
        "access_tokens.exists",
        () ->
            jdbi.withHandle(
                h ->
                    h.createQuery("SELECT 1 FROM access_tokens WHERE jti = :jti")
                        .bind("jti", jti)
                        .mapTo(Integer.class)
                        .findOne()
                        .isPresent()));
  }

  @Override
  public boolean delete(UserHandle userHandle, String jti) {
    if (jti == null) {
      return false;
    }
    return JdbiSupport.wrap(
        "access_tokens.delete",
        () ->
            jdbi.withHandle(
                h ->
                    h.createUpdate(
                                "DELETE FROM access_tokens"
                                    + " WHERE jti = :jti AND user_handle = :uh")
                            .bind("jti", jti)
                            .bind("uh", userHandle.value())
                            .execute()
                        > 0));
  }

  @Override
  public int deleteAllForUser(UserHandle userHandle) {
    return JdbiSupport.wrap(
        "access_tokens.deleteAllForUser",
        () ->
            jdbi.withHandle(
                h ->
                    h.createUpdate("DELETE FROM access_tokens WHERE user_handle = :uh")
                        .bind("uh", userHandle.value())
                        .execute()));
  }

  @Override
  public int deleteExpiredBefore(Instant before) {
    return JdbiSupport.wrap(
        "access_tokens.deleteExpiredBefore",
        () ->
            jdbi.withHandle(
                h ->
                    h.createUpdate("DELETE FROM access_tokens WHERE expires_at < :before")
                        .bind("before", OffsetDateTime.ofInstant(before, ZoneOffset.UTC))
                        .execute()));
  }
}
