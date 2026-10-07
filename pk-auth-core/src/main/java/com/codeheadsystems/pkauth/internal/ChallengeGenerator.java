// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.internal;

import java.security.SecureRandom;

/**
 * Produces WebAuthn challenge bytes. The challenge's store handle is a separate, random {@code
 * ChallengeId} (see {@link com.codeheadsystems.pkauth.api.ChallengeId#random()}); the id is
 * independent of the challenge bytes, so the store key never exposes the challenge and the
 * finish-time binding rests solely on the byte comparison in {@link ChallengeValidator}.
 *
 * <p>32 random bytes matches the WebAuthn level 3 recommendation of "at least 16 bytes" with
 * comfortable headroom.
 */
public final class ChallengeGenerator {

  static final int CHALLENGE_BYTES = 32;

  private final SecureRandom random;

  public ChallengeGenerator() {
    this(new SecureRandom());
  }

  /**
   * Test seam that accepts a {@link SecureRandom} for deterministic challenge generation in tests.
   */
  public ChallengeGenerator(SecureRandom random) {
    this.random = random;
  }

  /** Generates {@value #CHALLENGE_BYTES} random bytes for use as a WebAuthn challenge. */
  public byte[] generate() {
    byte[] challenge = new byte[CHALLENGE_BYTES];
    random.nextBytes(challenge);
    return challenge;
  }
}
