// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import com.fasterxml.jackson.annotation.JsonProperty;

/** WebAuthn {@code UserVerificationRequirement} enumeration (Level 3 §5.10.6). */
public enum UserVerificationRequirement {
  @JsonProperty("required")
  REQUIRED,
  @JsonProperty("preferred")
  PREFERRED,
  @JsonProperty("discouraged")
  DISCOURAGED
}
