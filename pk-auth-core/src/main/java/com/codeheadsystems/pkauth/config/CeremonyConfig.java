// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.config;

import com.codeheadsystems.pkauth.api.AttestationConveyance;
import com.codeheadsystems.pkauth.api.ResidentKeyRequirement;
import com.codeheadsystems.pkauth.api.UserVerificationRequirement;
import java.time.Duration;
import java.util.Objects;

/**
 * Ceremony-level policy knobs. Brief §7 documents the security-relevant defaults.
 *
 * @since 0.9.0
 */
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

  /**
   * Conservative defaults appropriate for a consumer passkey deployment.
   *
   * <p>{@code userVerification} defaults to {@link UserVerificationRequirement#REQUIRED} so
   * WebAuthn4J enforces the asserted {@code flagUV} on every assertion — a deployment that wants to
   * relax this (e.g. for hardware security keys without UV) must opt in explicitly.
   */
  public static CeremonyConfig defaults() {
    return new CeremonyConfig(
        DEFAULT_CHALLENGE_TTL,
        UserVerificationRequirement.REQUIRED,
        ResidentKeyRequirement.PREFERRED,
        AttestationConveyance.NONE,
        CounterRegressionPolicy.REJECT);
  }
}
