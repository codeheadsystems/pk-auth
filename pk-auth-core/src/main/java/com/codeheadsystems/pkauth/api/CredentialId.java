// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import com.codeheadsystems.pkauth.json.Base64Url;
import java.util.Arrays;
import java.util.Objects;

/**
 * WebAuthn credential identifier: an opaque byte sequence the authenticator assigns to a
 * credential.
 *
 * <p>The byte array is defensively copied on construction and on {@link #value()} so callers cannot
 * mutate the stored value. {@code equals} and {@code hashCode} are content-based, which the default
 * record implementation does not provide for array-valued components. This makes {@code
 * CredentialId} safe to use as a {@link java.util.Map} or {@link java.util.Set} key.
 *
 * @since 0.9.0
 */
public record CredentialId(byte[] value) {

  public CredentialId {
    Objects.requireNonNull(value, "value");
    if (value.length == 0) {
      throw new IllegalArgumentException("CredentialId value must be non-empty");
    }
    value = value.clone();
  }

  /** Factory for callers that prefer not to construct records directly. */
  public static CredentialId of(byte[] bytes) {
    return new CredentialId(bytes);
  }

  /** Parses a base64url-encoded credential id (no padding required). */
  public static CredentialId fromB64Url(String s) {
    Objects.requireNonNull(s, "s");
    return new CredentialId(Base64Url.decode(s));
  }

  @Override
  public byte[] value() {
    return value.clone();
  }

  /** Returns the URL-safe-no-padding Base64 encoding of the credential id bytes. */
  public String b64url() {
    return Base64Url.encode(value);
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof CredentialId other && Arrays.equals(this.value, other.value);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(value);
  }

  @Override
  public String toString() {
    return "CredentialId{b64url=" + Base64Url.encode(value) + "}";
  }
}
