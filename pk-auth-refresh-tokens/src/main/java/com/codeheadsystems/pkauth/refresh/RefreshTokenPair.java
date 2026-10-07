// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh;

import java.util.Objects;

/**
 * Result of issuing or rotating a refresh token. The {@link #wireToken()} is the only value that
 * goes to the client (the bearer presents it on the next refresh); the {@link #record()} is the
 * server-side projection (with hash, never the raw secret).
 *
 * @param wireToken the {@code "{refreshId}.{secret}"} string to return to the client; must never be
 *     logged
 * @param record the persisted shape (defensive copy of the hash, no raw secret)
 * @since 1.1.0
 */
public record RefreshTokenPair(String wireToken, RefreshTokenRecord record) {

  public RefreshTokenPair {
    Objects.requireNonNull(wireToken, "wireToken");
    Objects.requireNonNull(record, "record");
  }
}
