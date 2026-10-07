// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

/**
 * The authentication factor that produced the JWT. Wire spellings (lowercase, hyphen-separated) are
 * part of the public API.
 */
public enum AuthMethod {
  PASSKEY("passkey"),
  BACKUP_CODE("backup-code"),
  MAGIC_LINK("magic-link"),

  /**
   * Token minted as the access leg of a refresh-token rotation. The original auth method that
   * established the session is not preserved on the new JWT; hosts that care about provenance
   * should look it up via the refresh-token row.
   *
   * @since 1.1.0
   */
  REFRESH("refresh");

  private final String wireValue;

  AuthMethod(String wireValue) {
    this.wireValue = wireValue;
  }

  public String wireValue() {
    return wireValue;
  }

  /**
   * Parse a wire value back into an enum constant.
   *
   * @throws IllegalArgumentException if {@code value} is not a known wire value
   */
  public static AuthMethod fromWireValue(String value) {
    for (AuthMethod m : values()) {
      if (m.wireValue.equals(value)) {
        return m;
      }
    }
    throw new IllegalArgumentException("Unknown pkauth.method wire value: " + value);
  }
}
