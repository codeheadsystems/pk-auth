// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.config;

import com.codeheadsystems.pkauth.api.AttestationConveyance;
import com.codeheadsystems.pkauth.api.ResidentKeyRequirement;
import com.codeheadsystems.pkauth.api.UserVerificationRequirement;
import java.time.Duration;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

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

  /**
   * Builds a {@link CeremonyConfig} from raw host configuration where any knob the host left unset
   * is {@code null}. Each null field falls back to the conservative value from {@link #defaults()}
   * (e.g. {@code userVerification=REQUIRED}, {@code counterRegression=REJECT}); a {@code null}
   * never weakens a knob — a host must pass a non-null value to relax a default. Centralizes the
   * per-field default-coalescing every adapter previously performed by hand.
   *
   * @param challengeTtl challenge TTL, or null for the default.
   * @param userVerification UV requirement, or null for the default.
   * @param residentKey resident-key requirement, or null for the default.
   * @param attestationConveyance attestation conveyance, or null for the default.
   * @param counterRegression counter-regression policy, or null for the default.
   * @return the resolved ceremony config.
   * @since 2.0.0
   */
  public static CeremonyConfig from(
      @Nullable Duration challengeTtl,
      @Nullable UserVerificationRequirement userVerification,
      @Nullable ResidentKeyRequirement residentKey,
      @Nullable AttestationConveyance attestationConveyance,
      @Nullable CounterRegressionPolicy counterRegression) {
    CeremonyConfig d = defaults();
    return new CeremonyConfig(
        challengeTtl == null ? d.challengeTtl() : challengeTtl,
        userVerification == null ? d.userVerification() : userVerification,
        residentKey == null ? d.residentKey() : residentKey,
        attestationConveyance == null ? d.attestationConveyance() : attestationConveyance,
        counterRegression == null ? d.counterRegression() : counterRegression);
  }
}
