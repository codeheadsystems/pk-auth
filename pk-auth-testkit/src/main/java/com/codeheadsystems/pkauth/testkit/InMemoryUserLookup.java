// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.UserLookup;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link UserLookup} that mints a random user handle the first time it sees a username.
 */
public final class InMemoryUserLookup implements UserLookup {

  private final Map<String, UserView> byUsername = new ConcurrentHashMap<>();
  private final Map<UserHandle, UserView> byHandle = new ConcurrentHashMap<>();
  private final Map<UserHandle, String> emailByHandle = new ConcurrentHashMap<>();

  public InMemoryUserLookup() {}

  @Override
  public Optional<UserHandle> findHandleByUsername(String username) {
    UserView u = byUsername.get(username);
    return u == null ? Optional.empty() : Optional.of(u.handle());
  }

  @Override
  public Optional<String> emailFor(UserHandle handle) {
    return Optional.ofNullable(emailByHandle.get(handle));
  }

  @Override
  public Optional<UserView> findViewByHandle(UserHandle handle) {
    return Optional.ofNullable(byHandle.get(handle));
  }

  @Override
  public UserHandle getOrCreateHandle(String username) {
    UserView existing = byUsername.get(username);
    if (existing != null) {
      return existing.handle();
    }
    UserHandle handle = UserHandle.random();
    UserView view = new UserView(handle, username, username, false, false);
    UserView prior = byUsername.putIfAbsent(username, view);
    if (prior != null) {
      return prior.handle();
    }
    byHandle.put(handle, view);
    return handle;
  }

  /**
   * Test helper that lets a fixture pre-register a user with a specific handle and display name.
   */
  public UserHandle register(String username, String displayName) {
    UserHandle handle = UserHandle.random();
    UserView view = new UserView(handle, username, displayName, false, false);
    byUsername.put(username, view);
    byHandle.put(handle, view);
    return handle;
  }

  /**
   * Test helper that pre-registers a user with a bound email, exposed via {@link
   * #emailFor(UserHandle)}. Useful for flows (e.g. magic-link login) that deliver only to the
   * address bound to the resolved user.
   *
   * @since 2.1.0
   */
  public UserHandle register(String username, String displayName, String email) {
    UserHandle handle = register(username, displayName);
    emailByHandle.put(handle, email);
    return handle;
  }
}
