// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.UserLookup;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Objects;
import java.util.Optional;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.mapper.RowMapper;

/**
 * {@link UserLookup} backed by the demo {@code users} table (see {@code V5__example_users.sql}).
 * The brief notes that the users table is host-app data; this implementation is the reference
 * provided alongside the demo schema.
 */
public final class JdbiUserLookup implements UserLookup {

  private final Jdbi jdbi;

  public JdbiUserLookup(Jdbi jdbi) {
    this.jdbi = Objects.requireNonNull(jdbi, "jdbi");
  }

  @Override
  public Optional<UserHandle> findHandleByUsername(String username) {
    return JdbiSupport.wrap(
        "users.findHandleByUsername",
        () ->
            jdbi.withHandle(
                h ->
                    h.createQuery("SELECT user_handle FROM users WHERE username = :u")
                        .bind("u", username)
                        .mapTo(byte[].class)
                        .findFirst()
                        .map(UserHandle::of)));
  }

  @Override
  public Optional<UserView> findViewByHandle(UserHandle handle) {
    return JdbiSupport.wrap(
        "users.findViewByHandle",
        () ->
            jdbi.withHandle(
                h ->
                    h.createQuery("SELECT * FROM users WHERE user_handle = :uh")
                        .bind("uh", handle.value())
                        .map(VIEW_MAPPER)
                        .findFirst()));
  }

  @Override
  public UserHandle getOrCreateHandle(String username) {
    Objects.requireNonNull(username, "username");
    UserHandle candidate = UserHandle.random();
    return JdbiSupport.wrap(
        "users.getOrCreateHandle",
        () ->
            jdbi.withHandle(
                h -> {
                  byte[] handle =
                      h.createQuery(
                              "INSERT INTO users (user_handle, username, display_name) VALUES"
                                  + " (:uh, :u, :dn)"
                                  + " ON CONFLICT (username) DO UPDATE SET username ="
                                  + " EXCLUDED.username"
                                  + " RETURNING user_handle")
                          .bind("uh", candidate.value())
                          .bind("u", username)
                          .bind("dn", username)
                          .mapTo(byte[].class)
                          .one();
                  return UserHandle.of(handle);
                }));
  }

  /** Pre-registers a user with the supplied display name (test fixture support). */
  public UserHandle register(String username, String displayName) {
    UserHandle handle = UserHandle.random();
    JdbiSupport.wrap(
        "users.register",
        () -> {
          jdbi.useHandle(
              h ->
                  h.createUpdate(
                          "INSERT INTO users (user_handle, username, display_name) VALUES"
                              + " (:uh, :u, :dn)")
                      .bind("uh", handle.value())
                      .bind("u", username)
                      .bind("dn", displayName)
                      .execute());
          return null;
        });
    return handle;
  }

  private static final RowMapper<UserView> VIEW_MAPPER = (rs, ctx) -> readView(rs);

  private static UserView readView(ResultSet rs) throws SQLException {
    return new UserView(
        UserHandle.of(rs.getBytes("user_handle")),
        rs.getString("username"),
        rs.getString("display_name"),
        rs.getBoolean("email_verified"),
        rs.getBoolean("phone_verified"));
  }
}
