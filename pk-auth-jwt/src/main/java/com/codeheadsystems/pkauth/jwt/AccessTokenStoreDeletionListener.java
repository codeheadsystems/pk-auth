// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.lifecycle.UserDeletionListener;
import java.util.Objects;

/**
 * Bridges {@link AccessTokenStore#deleteAllForUser(UserHandle)} into the {@link
 * com.codeheadsystems.pkauth.lifecycle.UserDeletionService} fan-out. Lives in {@code pk-auth-jwt}
 * because the SPI does; {@code pk-auth-core} cannot depend on {@code pk-auth-jwt}.
 *
 * <p>Adapter modules register this listener whenever an {@link AccessTokenStore} bean is present
 * (which is always, since the default is {@link AccessTokenStore#noop()}); the noop store's {@code
 * deleteAllForUser} simply returns zero, so the listener is harmless in stateless deployments.
 *
 * @since 1.1.0
 */
public final class AccessTokenStoreDeletionListener implements UserDeletionListener {

  private final AccessTokenStore store;

  public AccessTokenStoreDeletionListener(AccessTokenStore store) {
    this.store = Objects.requireNonNull(store, "store");
  }

  @Override
  public void onUserDeleted(UserHandle userHandle) {
    store.deleteAllForUser(userHandle);
  }
}
