// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import com.fasterxml.jackson.annotation.JsonProperty;

/** WebAuthn {@code ResidentKeyRequirement} enumeration (Level 3 §5.4.6). */
public enum ResidentKeyRequirement {
  @JsonProperty("required")
  REQUIRED,
  @JsonProperty("preferred")
  PREFERRED,
  @JsonProperty("discouraged")
  DISCOURAGED
}
