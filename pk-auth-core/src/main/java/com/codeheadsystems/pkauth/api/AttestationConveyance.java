// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import com.fasterxml.jackson.annotation.JsonProperty;

/** WebAuthn {@code AttestationConveyancePreference} enumeration (Level 3 §5.4.7). */
public enum AttestationConveyance {
  @JsonProperty("none")
  NONE,
  @JsonProperty("indirect")
  INDIRECT,
  @JsonProperty("direct")
  DIRECT,
  @JsonProperty("enterprise")
  ENTERPRISE
}
