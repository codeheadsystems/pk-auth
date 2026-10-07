// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.time.Instant;
import java.util.Optional;

/**
 * Default {@link AccessTokenStore} that persists nothing and accepts every jti. Hosts that wire a
 * real store override this binding. The class is package-private; clients reach it via {@link
 * AccessTokenStore#noop()}.
 */
final class NoopAccessTokenStore implements AccessTokenStore {

  static final NoopAccessTokenStore INSTANCE = new NoopAccessTokenStore();

  private NoopAccessTokenStore() {}

  @Override
  public void record(
      String jti,
      UserHandle userHandle,
      String audience,
      Optional<String> deviceId,
      Instant issuedAt,
      Instant expiresAt) {
    // intentionally empty
  }

  @Override
  public boolean exists(String jti) {
    return true;
  }

  @Override
  public boolean delete(UserHandle userHandle, String jti) {
    return false;
  }

  @Override
  public int deleteAllForUser(UserHandle userHandle) {
    return 0;
  }

  @Override
  public int deleteExpiredBefore(Instant before) {
    return 0;
  }

  @Override
  public String toString() {
    return "AccessTokenStore.noop()";
  }
}
