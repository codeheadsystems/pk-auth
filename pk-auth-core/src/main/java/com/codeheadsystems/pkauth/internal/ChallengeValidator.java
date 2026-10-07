// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.internal;

import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.spi.ChallengeRecord;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.OriginValidator;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * Runs all preflight checks on a registration- or authentication-finish request before the heavy
 * WebAuthn4J verification is invoked.
 *
 * <p>Extracted from {@code DefaultPasskeyAuthenticationService} so the ceremony methods read as
 * {@code validate → verify → map → emit} without inlined bail-out branches.
 *
 * <p>The validator is stateless beyond its collaborators. Each {@link #validate} call:
 *
 * <ol>
 *   <li>parses the client-supplied {@code clientDataJSON};
 *   <li>checks the ceremony marker (registration vs authentication);
 *   <li>checks the origin against {@link OriginValidator};
 *   <li>consumes the {@link ChallengeRecord} via {@link ChallengeStore#takeOnce} (one-shot; even on
 *       later failure the record is gone), keyed by the opaque {@link ChallengeId} the client
 *       round-trips from the start response;
 *   <li>checks the stored record's purpose, byte equality (the cryptographic binding between the
 *       stored challenge and the bytes the authenticator signed), and expiry.
 * </ol>
 *
 * <p>The caller maps the returned {@link ChallengeValidation} variant to the result hierarchy that
 * fits the ceremony (registration vs authentication).
 */
public final class ChallengeValidator {

  /**
   * Ceremony marker the validator should accept in {@code clientData.type}. Also carries the
   * canonical phase string used in metric names and structured log lines so callers never have to
   * concatenate {@code "pkauth." + phase + ".outcome"} by hand.
   *
   * @since 0.9.1
   */
  public enum Ceremony {
    REGISTRATION("webauthn.create", ChallengeRecord.Purpose.REGISTRATION, "registration"),
    AUTHENTICATION("webauthn.get", ChallengeRecord.Purpose.AUTHENTICATION, "authentication");

    private final String clientDataType;
    private final ChallengeRecord.Purpose purpose;
    private final String metricPhase;
    private final String outcomeCounterName;
    private final String durationTimerName;

    Ceremony(String clientDataType, ChallengeRecord.Purpose purpose, String metricPhase) {
      this.clientDataType = clientDataType;
      this.purpose = purpose;
      this.metricPhase = metricPhase;
      this.outcomeCounterName = "pkauth." + metricPhase + ".outcome";
      this.durationTimerName = "pkauth." + metricPhase + ".duration";
    }

    public String clientDataType() {
      return clientDataType;
    }

    public ChallengeRecord.Purpose purpose() {
      return purpose;
    }

    /**
     * Canonical phase token (e.g. {@code "registration"}) used both as a structured-log field and
     * as the segment of every {@code pkauth.<phase>.*} metric name.
     *
     * @since 0.9.1
     */
    public String metricPhase() {
      return metricPhase;
    }

    /**
     * Fully-qualified metric name for the per-ceremony "outcome" counter ({@code
     * pkauth.<phase>.outcome}).
     *
     * @since 0.9.1
     */
    public String outcomeCounterName() {
      return outcomeCounterName;
    }

    /**
     * Fully-qualified metric name for the per-ceremony "duration" timer ({@code
     * pkauth.<phase>.duration}).
     *
     * @since 0.9.1
     */
    public String durationTimerName() {
      return durationTimerName;
    }
  }

  private final ChallengeStore challengeStore;
  private final OriginValidator originValidator;
  private final ClockProvider clockProvider;

  public ChallengeValidator(
      ChallengeStore challengeStore, OriginValidator originValidator, ClockProvider clockProvider) {
    this.challengeStore = Objects.requireNonNull(challengeStore, "challengeStore");
    this.originValidator = Objects.requireNonNull(originValidator, "originValidator");
    this.clockProvider = Objects.requireNonNull(clockProvider, "clockProvider");
  }

  /**
   * Validates a finish-ceremony request.
   *
   * @param ceremony which ceremony this finish belongs to
   * @param challengeId the explicit challenge id sent on the request
   * @param clientDataJson raw client data bytes from the WebAuthn response
   */
  public ChallengeValidation validate(
      Ceremony ceremony, ChallengeId challengeId, byte[] clientDataJson) {
    Objects.requireNonNull(ceremony, "ceremony");
    Objects.requireNonNull(challengeId, "challengeId");
    Objects.requireNonNull(clientDataJson, "clientDataJson");

    ClientDataJsonParser.ClientData clientData;
    try {
      clientData = ClientDataJsonParser.parse(clientDataJson);
    } catch (RuntimeException ex) {
      return new ChallengeValidation.MalformedClientData("malformed clientDataJSON");
    }

    if (!ceremony.clientDataType().equals(clientData.type())) {
      return new ChallengeValidation.CeremonyTypeMismatch(
          ceremony.clientDataType(), String.valueOf(clientData.type()));
    }

    if (!originValidator.isAllowed(clientData.origin())) {
      return new ChallengeValidation.OriginMismatch(clientData.origin());
    }

    byte[] challengeBytes;
    try {
      challengeBytes = clientData.challengeBytes();
    } catch (RuntimeException ex) {
      return new ChallengeValidation.InvalidEncoding("invalid challenge encoding");
    }

    // The challengeId is an opaque, server-generated handle (random UUID) independent of the
    // challenge bytes. Look the record up by it, then enforce the cryptographic binding below by
    // byte-comparing the stored challenge against the bytes the authenticator actually signed over
    // (clientData.challenge) — WebAuthn4J independently re-checks the same challenge during
    // signature verification.
    Optional<ChallengeRecord> stored = challengeStore.takeOnce(challengeId);
    if (stored.isEmpty()) {
      return new ChallengeValidation.MissingOrConsumed();
    }
    ChallengeRecord record = stored.get();

    if (record.purpose() != ceremony.purpose()) {
      return new ChallengeValidation.PurposeMismatch();
    }
    if (!Arrays.equals(record.challenge(), challengeBytes)) {
      return new ChallengeValidation.BytesMismatch();
    }
    if (clockProvider.now().isAfter(record.expiresAt())) {
      return new ChallengeValidation.Expired();
    }

    return new ChallengeValidation.Valid(record, clientData);
  }
}
