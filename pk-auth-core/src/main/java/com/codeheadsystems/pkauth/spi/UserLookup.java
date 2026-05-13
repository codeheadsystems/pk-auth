// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.util.Objects;
import java.util.Optional;

/**
 * Host-app integration point that maps usernames to pk-auth user handles. pk-auth does not own the
 * users table; the host application is the source of truth.
 */
public interface UserLookup {

  Optional<UserHandle> findUserHandleByUsername(String username);

  Optional<UserView> findUserByHandle(UserHandle handle);

  /** Returns an existing user handle for {@code username} or creates and returns a new one. */
  UserHandle createOrGetUserHandle(String username);

  /** Read-only projection of host-app user state pk-auth needs for ceremonies and admin flows. */
  record UserView(
      UserHandle handle,
      String username,
      String displayName,
      boolean emailVerified,
      boolean phoneVerified) {
    public UserView {
      Objects.requireNonNull(handle, "handle");
      Objects.requireNonNull(username, "username");
      Objects.requireNonNull(displayName, "displayName");
    }
  }
}
