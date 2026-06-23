// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.config;

import com.codeheadsystems.pkauth.api.AttestationConveyance;
import com.codeheadsystems.pkauth.api.ResidentKeyRequirement;
import com.codeheadsystems.pkauth.api.UserVerificationRequirement;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Ceremony-level policy knobs. Brief §7 documents the security-relevant defaults.
 *
 * <p><strong>Crypto-agility.</strong> {@link #offeredAlgorithms()} and {@link
 * #acceptedAlgorithms()} are the single source of truth for which COSE signature algorithms a
 * deployment advertises in the create-options ceremony and accepts on registration verification,
 * respectively. Both the create-options path and the WebAuthn4J verify path derive their algorithm
 * lists from this config — there are no hardcoded algorithm lists elsewhere. The {@code accepted}
 * list is authoritative (a credential whose algorithm is absent from it is rejected on verify);
 * {@code offered} must be a subset of {@code accepted} and may be narrower so a deployment can
 * advertise fewer algorithms than it still honors for already-registered credentials. See {@code
 * docs/threat-model.md} (Post-quantum readiness) and ADR 0019.
 *
 * @since 0.9.0
 */
public record CeremonyConfig(
    Duration challengeTtl,
    UserVerificationRequirement userVerification,
    ResidentKeyRequirement residentKey,
    AttestationConveyance attestationConveyance,
    CounterRegressionPolicy counterRegression,
    List<CoseAlgorithm> offeredAlgorithms,
    List<CoseAlgorithm> acceptedAlgorithms) {

  /** Default TTL for a ceremony challenge: 5 minutes. */
  public static final Duration DEFAULT_CHALLENGE_TTL = Duration.ofMinutes(5);

  /**
   * Algorithms offered to the authenticator in the registration create-options ({@code
   * PublicKeyCredentialParameters}). The historical offered set: ES256, EdDSA, RS256. Deliberately
   * a subset of {@link #DEFAULT_ACCEPTED_ALGORITHMS}.
   *
   * @since 2.1.0
   */
  public static final List<CoseAlgorithm> DEFAULT_OFFERED_ALGORITHMS =
      List.of(CoseAlgorithm.ES256, CoseAlgorithm.EdDSA, CoseAlgorithm.RS256);

  /**
   * Algorithms accepted on registration verification — the source of truth. The default is the
   * historical {@code WebAuthn4JConverters} verify set: ES256, EdDSA, RS256, ES384, RS384. It is
   * the <em>union</em> of everything previously accepted so no already-registered credential can
   * fail verification.
   *
   * @since 2.1.0
   */
  public static final List<CoseAlgorithm> DEFAULT_ACCEPTED_ALGORITHMS =
      List.of(
          CoseAlgorithm.ES256,
          CoseAlgorithm.EdDSA,
          CoseAlgorithm.RS256,
          CoseAlgorithm.ES384,
          CoseAlgorithm.RS384);

  public CeremonyConfig {
    Objects.requireNonNull(challengeTtl, "challengeTtl");
    if (challengeTtl.isZero() || challengeTtl.isNegative()) {
      throw new IllegalArgumentException("challengeTtl must be positive");
    }
    Objects.requireNonNull(userVerification, "userVerification");
    Objects.requireNonNull(residentKey, "residentKey");
    Objects.requireNonNull(attestationConveyance, "attestationConveyance");
    Objects.requireNonNull(counterRegression, "counterRegression");
    Objects.requireNonNull(offeredAlgorithms, "offeredAlgorithms");
    Objects.requireNonNull(acceptedAlgorithms, "acceptedAlgorithms");
    offeredAlgorithms = List.copyOf(offeredAlgorithms);
    acceptedAlgorithms = List.copyOf(acceptedAlgorithms);
    if (acceptedAlgorithms.isEmpty()) {
      throw new IllegalArgumentException("acceptedAlgorithms must contain at least one algorithm");
    }
    if (!acceptedAlgorithms.containsAll(offeredAlgorithms)) {
      throw new IllegalArgumentException(
          "offeredAlgorithms must be a subset of acceptedAlgorithms (cannot offer an algorithm that"
              + " would be rejected on verify)");
    }
  }

  /**
   * Backward-compatible constructor that applies {@link #DEFAULT_OFFERED_ALGORITHMS} and {@link
   * #DEFAULT_ACCEPTED_ALGORITHMS}. Existing call sites that predate the crypto-agility fields keep
   * compiling and keep the exact historical algorithm behavior; pass the seven-argument canonical
   * constructor (or {@link #from}) to override the algorithm lists.
   *
   * @since 0.9.0
   */
  public CeremonyConfig(
      Duration challengeTtl,
      UserVerificationRequirement userVerification,
      ResidentKeyRequirement residentKey,
      AttestationConveyance attestationConveyance,
      CounterRegressionPolicy counterRegression) {
    this(
        challengeTtl,
        userVerification,
        residentKey,
        attestationConveyance,
        counterRegression,
        DEFAULT_OFFERED_ALGORITHMS,
        DEFAULT_ACCEPTED_ALGORITHMS);
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
        CounterRegressionPolicy.REJECT,
        DEFAULT_OFFERED_ALGORITHMS,
        DEFAULT_ACCEPTED_ALGORITHMS);
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
    return from(
        challengeTtl,
        userVerification,
        residentKey,
        attestationConveyance,
        counterRegression,
        null,
        null);
  }

  /**
   * Crypto-agility-aware overload of {@link #from(Duration, UserVerificationRequirement,
   * ResidentKeyRequirement, AttestationConveyance, CounterRegressionPolicy)} that also lets a host
   * narrow or reorder the COSE algorithm lists. A {@code null} {@code offeredAlgorithms} / {@code
   * acceptedAlgorithms} falls back to {@link #DEFAULT_OFFERED_ALGORITHMS} / {@link
   * #DEFAULT_ACCEPTED_ALGORITHMS}, preserving the historical algorithm behavior.
   *
   * @param challengeTtl challenge TTL, or null for the default.
   * @param userVerification UV requirement, or null for the default.
   * @param residentKey resident-key requirement, or null for the default.
   * @param attestationConveyance attestation conveyance, or null for the default.
   * @param counterRegression counter-regression policy, or null for the default.
   * @param offeredAlgorithms algorithms advertised in create-options, or null for the default.
   * @param acceptedAlgorithms algorithms accepted on verify, or null for the default.
   * @return the resolved ceremony config.
   * @since 2.1.0
   */
  public static CeremonyConfig from(
      @Nullable Duration challengeTtl,
      @Nullable UserVerificationRequirement userVerification,
      @Nullable ResidentKeyRequirement residentKey,
      @Nullable AttestationConveyance attestationConveyance,
      @Nullable CounterRegressionPolicy counterRegression,
      @Nullable List<CoseAlgorithm> offeredAlgorithms,
      @Nullable List<CoseAlgorithm> acceptedAlgorithms) {
    CeremonyConfig d = defaults();
    return new CeremonyConfig(
        challengeTtl == null ? d.challengeTtl() : challengeTtl,
        userVerification == null ? d.userVerification() : userVerification,
        residentKey == null ? d.residentKey() : residentKey,
        attestationConveyance == null ? d.attestationConveyance() : attestationConveyance,
        counterRegression == null ? d.counterRegression() : counterRegression,
        offeredAlgorithms == null ? d.offeredAlgorithms() : offeredAlgorithms,
        acceptedAlgorithms == null ? d.acceptedAlgorithms() : acceptedAlgorithms);
  }
}
