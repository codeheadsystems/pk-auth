// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import com.codeheadsystems.pkauth.api.ChallengeId;
import java.time.Duration;
import java.util.Optional;

/**
 * Single-use challenge store. Implementations must enforce atomic single-use semantics in {@link
 * #takeOnce} — reading a challenge MUST remove it from the store in the same operation to prevent
 * replay.
 */
public interface ChallengeStore {

  void put(ChallengeId id, ChallengeRecord record, Duration ttl);

  /**
   * Atomically remove and return the challenge bound to {@code id}, if present. Returns empty if
   * the id was never stored, has already been consumed, or has expired.
   */
  Optional<ChallengeRecord> takeOnce(ChallengeId id);
}
