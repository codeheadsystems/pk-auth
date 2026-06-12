// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import com.codeheadsystems.pkauth.api.ChallengeId;
import java.time.Duration;
import java.util.Optional;

/**
 * Single-use challenge store. Implementations must enforce atomic single-use semantics in {@link
 * #takeOnce} — reading a challenge MUST remove it from the store in the same operation to prevent
 * replay.
 *
 * @since 0.9.0
 */
public interface ChallengeStore {

  /**
   * Stores {@code record} under {@code id} with the given {@code ttl}. Replaces any existing entry
   * bound to the same id (last-writer-wins).
   *
   * <p><strong>Overwrite semantics.</strong> A {@code ChallengeId} is generated server-side and is
   * cryptographically unique per ceremony, so collisions in normal operation indicate a deliberate
   * retry by the same caller. Overwriting on collision is the safer choice in that case because it
   * invalidates the prior challenge (which {@link #takeOnce} would otherwise still accept).
   * Implementations MUST replace the prior record atomically — there must be no window in which
   * {@code takeOnce} could return the old record after this method returns.
   *
   * <p><strong>TTL.</strong> {@code ttl} must be strictly positive. Zero or negative values are
   * rejected with {@link IllegalArgumentException}; a non-positive TTL would expose a challenge
   * that is immediately replayable (or worse, never expires by clock arithmetic), which defeats the
   * single-use guarantee. Callers that want to "never store" should simply not call this method.
   *
   * @param id the challenge identifier; must be non-null
   * @param record the challenge payload; must be non-null
   * @param ttl positive lifetime of the entry; must be non-null
   * @throws IllegalArgumentException if {@code ttl} is zero or negative
   * @throws NullPointerException if any argument is null
   * @since 0.9.1
   */
  void put(ChallengeId id, ChallengeRecord record, Duration ttl);

  /**
   * Atomically remove and return the challenge bound to {@code id}, if present. Returns empty if
   * the id was never stored, has already been consumed, or has expired.
   */
  Optional<ChallengeRecord> takeOnce(ChallengeId id);
}
