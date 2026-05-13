// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * WebAuthn user handle: an opaque 1-64 byte identifier the relying party assigns to a user.
 *
 * <p>The byte array is defensively copied on construction and on {@link #value()} so callers cannot
 * mutate the stored value. {@code equals} and {@code hashCode} are content-based, which the default
 * record implementation does not provide for array-valued components.
 */
public record UserHandle(byte[] value) {

  private static final SecureRandom RANDOM = new SecureRandom();

  /** Minimum length of a user handle, per WebAuthn Level 3 §5.1.2. */
  public static final int MIN_LENGTH = 1;

  /** Maximum length of a user handle, per WebAuthn Level 3 §5.1.2. */
  public static final int MAX_LENGTH = 64;

  public UserHandle {
    Objects.requireNonNull(value, "value");
    if (value.length < MIN_LENGTH || value.length > MAX_LENGTH) {
      throw new IllegalArgumentException(
          "UserHandle length must be between "
              + MIN_LENGTH
              + " and "
              + MAX_LENGTH
              + " bytes, was "
              + value.length);
    }
    value = value.clone();
  }

  /** Factory for callers that prefer not to construct records directly. */
  public static UserHandle of(byte[] value) {
    return new UserHandle(value);
  }

  /** Generates a cryptographically random 16-byte user handle. */
  public static UserHandle random() {
    byte[] bytes = new byte[16];
    RANDOM.nextBytes(bytes);
    return new UserHandle(bytes);
  }

  @Override
  public byte[] value() {
    return value.clone();
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof UserHandle other && Arrays.equals(this.value, other.value);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(value);
  }

  @Override
  public String toString() {
    return "UserHandle(" + HexFormat.of().formatHex(value) + ")";
  }
}
