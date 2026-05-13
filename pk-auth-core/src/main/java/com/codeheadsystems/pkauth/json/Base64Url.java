// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.json;

import java.util.Base64;
import java.util.Objects;

/**
 * RFC 4648 §5 base64url codec with padding stripped. WebAuthn JSON uses the no-padding form for
 * every binary field; pk-auth uses this codec uniformly for both serialization and any
 * application-level base64url conversions.
 */
public final class Base64Url {

  private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

  private Base64Url() {}

  /** Encodes {@code bytes} as base64url with no trailing {@code =} padding. */
  public static String encode(byte[] bytes) {
    Objects.requireNonNull(bytes, "bytes");
    return ENCODER.encodeToString(bytes);
  }

  /** Decodes {@code text}. Tolerates input that includes padding for backwards compatibility. */
  public static byte[] decode(String text) {
    Objects.requireNonNull(text, "text");
    return DECODER.decode(text);
  }
}
