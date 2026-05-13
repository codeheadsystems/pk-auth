// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.config;

import com.codeheadsystems.pkauth.api.AttestationConveyance;
import com.codeheadsystems.pkauth.api.ResidentKeyRequirement;
import com.codeheadsystems.pkauth.api.UserVerificationRequirement;
import java.time.Duration;
import java.util.Objects;

/** Ceremony-level policy knobs. Brief §7 documents the security-relevant defaults. */
public record CeremonyConfig(
    Duration challengeTtl,
    UserVerificationRequirement userVerification,
    ResidentKeyRequirement residentKey,
    AttestationConveyance attestationConveyance,
    CounterRegressionPolicy counterRegression) {

  /** Default TTL for a ceremony challenge: 5 minutes. */
  public static final Duration DEFAULT_CHALLENGE_TTL = Duration.ofMinutes(5);

  public CeremonyConfig {
    Objects.requireNonNull(challengeTtl, "challengeTtl");
    if (challengeTtl.isZero() || challengeTtl.isNegative()) {
      throw new IllegalArgumentException("challengeTtl must be positive");
    }
    Objects.requireNonNull(userVerification, "userVerification");
    Objects.requireNonNull(residentKey, "residentKey");
    Objects.requireNonNull(attestationConveyance, "attestationConveyance");
    Objects.requireNonNull(counterRegression, "counterRegression");
  }

  /** Conservative defaults appropriate for a consumer passkey deployment. */
  public static CeremonyConfig defaults() {
    return new CeremonyConfig(
        DEFAULT_CHALLENGE_TTL,
        UserVerificationRequirement.PREFERRED,
        ResidentKeyRequirement.PREFERRED,
        AttestationConveyance.NONE,
        CounterRegressionPolicy.REJECT);
  }
}
