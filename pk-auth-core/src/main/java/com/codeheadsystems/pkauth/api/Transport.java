// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import java.util.Objects;
import java.util.Optional;
import org.jspecify.annotations.Nullable;

/**
 * WebAuthn {@code AuthenticatorTransport} values, per the Level 3 spec §5.8.4. Each constant knows
 * its wire-string form via {@link #wireName()}; parsing from the wire is done with {@link
 * #fromWire(String)}.
 */
public enum Transport {
  USB("usb"),
  NFC("nfc"),
  BLE("ble"),
  INTERNAL("internal"),
  HYBRID("hybrid"),
  SMART_CARD("smart-card");

  private final String wireName;

  Transport(String wireName) {
    this.wireName = wireName;
  }

  /** Returns the WebAuthn-defined wire string for this transport. */
  public String wireName() {
    return wireName;
  }

  /**
   * Parses a WebAuthn transport wire string into a {@code Transport}. Returns {@link
   * Optional#empty()} when the string is null or not a recognized value (e.g. when an authenticator
   * advertises a future transport this enum does not yet enumerate).
   */
  public static Optional<Transport> fromWire(@Nullable String s) {
    if (s == null) {
      return Optional.empty();
    }
    for (Transport t : values()) {
      if (Objects.equals(t.wireName, s)) {
        return Optional.of(t);
      }
    }
    return Optional.empty();
  }
}
