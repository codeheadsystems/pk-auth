// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import java.util.Objects;
import java.util.UUID;

/** Opaque identifier for an in-flight WebAuthn challenge in the {@code ChallengeStore}. */
public record ChallengeId(String value) {

  public ChallengeId {
    Objects.requireNonNull(value, "value");
    if (value.isEmpty()) {
      throw new IllegalArgumentException("ChallengeId value must be non-empty");
    }
  }

  /** Generates a random ChallengeId backed by a {@link UUID}. */
  public static ChallengeId random() {
    return new ChallengeId(UUID.randomUUID().toString());
  }
}
