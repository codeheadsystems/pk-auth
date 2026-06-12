// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * WebAuthn {@code AuthenticatorAttachment} enumeration (Level 3 §5.4.5).
 *
 * @since 0.9.0
 */
public enum AuthenticatorAttachment {
  @JsonProperty("platform")
  PLATFORM,
  @JsonProperty("cross-platform")
  CROSS_PLATFORM
}
