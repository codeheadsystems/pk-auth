// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.internal;

import com.codeheadsystems.pkauth.api.AssertionResult;
import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.PublicKeyCredentialCreationOptionsJson;
import com.codeheadsystems.pkauth.api.PublicKeyCredentialCreationOptionsJson.AuthenticatorSelectionCriteria;
import com.codeheadsystems.pkauth.api.PublicKeyCredentialCreationOptionsJson.PublicKeyCredentialDescriptor;
import com.codeheadsystems.pkauth.api.PublicKeyCredentialCreationOptionsJson.PublicKeyCredentialParameters;
import com.codeheadsystems.pkauth.api.PublicKeyCredentialCreationOptionsJson.RelyingParty;
import com.codeheadsystems.pkauth.api.PublicKeyCredentialCreationOptionsJson.UserInfo;
import com.codeheadsystems.pkauth.api.PublicKeyCredentialRequestOptionsJson;
import com.codeheadsystems.pkauth.api.RegistrationResult;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResponse;
import com.codeheadsystems.pkauth.api.StartAuthenticationResult;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResponse;
import com.codeheadsystems.pkauth.api.StartRegistrationResult;
import com.codeheadsystems.pkauth.api.Transport;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.api.UserVerificationRequirement;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.config.CeremonyConfig;
import com.codeheadsystems.pkauth.config.CounterRegressionPolicy;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.credential.AuthenticatorData;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.metrics.Metrics;
import com.codeheadsystems.pkauth.spi.AttestationTrustPolicy;
import com.codeheadsystems.pkauth.spi.CeremonyRateLimiter;
import com.codeheadsystems.pkauth.spi.ChallengeRecord;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.DuplicateCredentialException;
import com.codeheadsystems.pkauth.spi.OriginValidator;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.verifier.exception.BadChallengeException;
import com.webauthn4j.verifier.exception.BadOriginException;
import com.webauthn4j.verifier.exception.MaliciousCounterValueException;
import com.webauthn4j.verifier.exception.MissingChallengeException;
import com.webauthn4j.verifier.exception.UserNotVerifiedException;
import com.webauthn4j.verifier.exception.VerificationException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.core.JacksonException;

/**
 * Default {@link PasskeyAuthenticationService} backed by WebAuthn4J's {@link WebAuthnManager}.
 *
 * <p>Instances are constructed via {@link
 * com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationServices} (the public factory in the
 * {@code ceremony} package).
 *
 * <p>The two finish-ceremony methods follow a four-step shape:
 *
 * <pre>
 *   validate (ChallengeValidator) → verify (WebAuthn4J) → map (sealed result) → emit (metrics)
 * </pre>
 *
 * Preflight challenge / origin / ceremony-type checks live on {@link ChallengeValidator}; this
 * class only translates {@link ChallengeValidation} variants into the ceremony's result type and
 * runs the WebAuthn4J verification + persistence steps.
 */
public final class DefaultPasskeyAuthenticationService implements PasskeyAuthenticationService {

  private static final Logger LOG =
      LoggerFactory.getLogger(DefaultPasskeyAuthenticationService.class);

  /**
   * Client-side {@code timeout} hint sent in the WebAuthn options. Independent of {@link
   * CeremonyConfig#challengeTtl()}, the server-side challenge lifetime. The challenge TTL should be
   * at least this long so a challenge never expires while the browser prompt is still open.
   */
  private static final long DEFAULT_TIMEOUT_MS = 60_000L;

  private static final String COUNTER_REGRESSED_OUTCOME = "success_counter_regressed";

  private final WebAuthnManager webAuthnManager;
  private final ObjectConverter objectConverter;
  private final CredentialRepository credentialRepository;
  private final UserLookup userLookup;
  private final ChallengeStore challengeStore;
  private final ClockProvider clockProvider;
  private final AttestationTrustPolicy attestationTrustPolicy;
  private final RelyingPartyConfig rpConfig;
  private final CeremonyConfig ceremonyConfig;
  private final ChallengeGenerator challengeGenerator;
  private final Metrics metrics;
  private final ChallengeValidator challengeValidator;
  private final CeremonyRateLimiter rateLimiter;

  /**
   * Full-control constructor. The supplied {@link CeremonyRateLimiter} is consulted on every
   * entrypoint; when it denies, the ceremony short-circuits before any challenge / repository
   * interaction.
   *
   * @since 0.9.1
   */
  public DefaultPasskeyAuthenticationService(
      WebAuthnManager webAuthnManager,
      ObjectConverter objectConverter,
      CredentialRepository credentialRepository,
      UserLookup userLookup,
      ChallengeStore challengeStore,
      ClockProvider clockProvider,
      OriginValidator originValidator,
      AttestationTrustPolicy attestationTrustPolicy,
      RelyingPartyConfig rpConfig,
      CeremonyConfig ceremonyConfig,
      ChallengeGenerator challengeGenerator,
      Metrics metrics,
      CeremonyRateLimiter rateLimiter) {
    this.webAuthnManager = Objects.requireNonNull(webAuthnManager, "webAuthnManager");
    this.objectConverter = Objects.requireNonNull(objectConverter, "objectConverter");
    this.credentialRepository =
        Objects.requireNonNull(credentialRepository, "credentialRepository");
    this.userLookup = Objects.requireNonNull(userLookup, "userLookup");
    this.challengeStore = Objects.requireNonNull(challengeStore, "challengeStore");
    this.clockProvider = Objects.requireNonNull(clockProvider, "clockProvider");
    this.attestationTrustPolicy =
        Objects.requireNonNull(attestationTrustPolicy, "attestationTrustPolicy");
    this.rpConfig = Objects.requireNonNull(rpConfig, "rpConfig");
    this.ceremonyConfig = Objects.requireNonNull(ceremonyConfig, "ceremonyConfig");
    this.challengeGenerator = Objects.requireNonNull(challengeGenerator, "challengeGenerator");
    this.metrics = Objects.requireNonNull(metrics, "metrics");
    this.rateLimiter = Objects.requireNonNull(rateLimiter, "rateLimiter");
    this.challengeValidator =
        new ChallengeValidator(challengeStore, originValidator, clockProvider);
  }

  // -- Registration ----------------------------------------------------------------------------

  /**
   * Starts a passkey registration ceremony.
   *
   * <p>Privacy invariant: {@code excludeCredentials} on the returned options is always a (possibly
   * empty) list, never {@code null}. Emitting {@code null} for brand-new usernames while emitting a
   * populated list for existing users on this {@code permitAll} endpoint would create an
   * account-enumeration oracle. Mirrors the same privacy guard in {@code
   * MagicLinkService.startLogin}.
   *
   * @since 0.9.1
   */
  @Override
  public StartRegistrationResult startRegistration(
      StartRegistrationRequest req, @Nullable String clientIp) {
    Objects.requireNonNull(req, "req");
    String deniedBucket = rateLimitedBucket("registration.start", clientIp, req.username());
    if (deniedBucket != null) {
      return new StartRegistrationResult.RateLimited(deniedBucket);
    }
    UserHandle userHandle = userLookup.getOrCreateHandle(req.username());

    IssuedChallenge issued =
        issueChallenge(ChallengeRecord.Purpose.REGISTRATION, userHandle, req.userVerification());

    // Always non-null: brand-new usernames yield an empty list rather than null so the wire
    // shape is indistinguishable from an existing user with no exclusions. Prevents account
    // enumeration on the public start-registration endpoint.
    List<PublicKeyCredentialDescriptor> excludeCredentials = descriptorsFor(userHandle);

    AuthenticatorSelectionCriteria selection =
        new AuthenticatorSelectionCriteria(
            null, ceremonyConfig.residentKey(), null, issued.userVerification());

    PublicKeyCredentialCreationOptionsJson options =
        new PublicKeyCredentialCreationOptionsJson(
            new RelyingParty(rpConfig.id(), rpConfig.name()),
            new UserInfo(
                userHandle.value(),
                req.username(),
                req.displayName() == null ? req.username() : req.displayName()),
            issued.challenge(),
            // Crypto-agility: the offered algorithm list comes from CeremonyConfig, not a hardcoded
            // literal. Same source of truth the verify path reads (the accepted list); see
            // WebAuthn4JConverters.pubKeyCredParams and ADR 0019.
            ceremonyConfig.offeredAlgorithms().stream()
                .map(a -> new PublicKeyCredentialParameters("public-key", a.coseValue()))
                .toList(),
            DEFAULT_TIMEOUT_MS,
            excludeCredentials,
            selection,
            ceremonyConfig.attestationConveyance(),
            null);

    metrics.incrementCounter("pkauth.registration.start", "rp", rpConfig.id());
    LOG.info("registration.start userHandle={} challengeId={}", userHandle, issued.id().value());
    return new StartRegistrationResult.Started(new StartRegistrationResponse(issued.id(), options));
  }

  @Override
  public RegistrationResult finishRegistration(
      FinishRegistrationRequest req, @Nullable String clientIp) {
    Objects.requireNonNull(req, "req");
    long start = System.nanoTime();
    ChallengeValidator.Ceremony ceremony = ChallengeValidator.Ceremony.REGISTRATION;
    if (!rateLimiter.tryAcquireForIp(clientIp)) {
      LOG.info("registration.finish rate-limited ip-bucket clientIp={}", clientIp);
      return emitOutcome(ceremony, new RegistrationResult.RateLimited("ip"), start);
    }
    // Step 0: bound the caller-supplied label before anything else. Checked ahead of the challenge
    // preflight on purpose — takeOnce is single-use, so validating first means an over-long label
    // doesn't burn the challenge and force a full ceremony restart.
    String label = req.label();
    if (label != null && label.length() > CredentialRecord.MAX_LABEL_LENGTH) {
      return emitOutcome(
          ceremony,
          new RegistrationResult.InvalidPayload(
              "label must be at most " + CredentialRecord.MAX_LABEL_LENGTH + " characters"),
          start);
    }

    // Step 1: challenge / origin / ceremony-type preflight.
    ChallengeValidation validation =
        challengeValidator.validate(
            ceremony, req.challengeId(), req.response().response().clientDataJSON());
    if (!(validation instanceof ChallengeValidation.Valid valid)) {
      return emitOutcome(ceremony, mapRegistrationPreflight(validation), start);
    }

    // Step 2: WebAuthn4J cryptographic verification.
    RegistrationData data;
    try {
      data = verifyRegistrationWithW4j(req, valid.record());
    } catch (DataConversionException | JacksonException | VerificationException ex) {
      return emitOutcome(ceremony, mapRegistrationException(ex, valid.clientData()), start);
    }

    // Step 3: attestation policy + duplicate-credential check.
    AttestedCredentialData acd;
    switch (evaluateAttestation(data)) {
      case AttestationEvaluation.Rejected rejected -> {
        return emitOutcome(ceremony, rejected.result(), start);
      }
      case AttestationEvaluation.Accepted accepted -> acd = accepted.attestedCredentialData();
    }

    // Step 4: persist the new credential and build the success result.
    return emitOutcome(ceremony, persistRegistration(req, valid.record(), data, acd), start);
  }

  /**
   * Hands the registration response off to WebAuthn4J for cryptographic verification. Throws the
   * WebAuthn4J exception types the caller maps to specific result variants; programming errors
   * propagate.
   */
  private RegistrationData verifyRegistrationWithW4j(
      FinishRegistrationRequest req, ChallengeRecord challengeRecord) {
    var w4jRequest = WebAuthn4JConverters.toRegistrationRequest(req.response());
    var serverProperty = WebAuthn4JConverters.serverProperty(rpConfig, challengeRecord.challenge());
    var w4jParams =
        new RegistrationParameters(
            serverProperty,
            WebAuthn4JConverters.pubKeyCredParams(ceremonyConfig.acceptedAlgorithms()),
            effectiveUserVerificationRequired(challengeRecord),
            /* userPresenceRequired */ true);
    // Attestation signature verification is intentionally non-strict in the default manager, so
    // BadSignatureException is not thrown here; hosts opt into strict attestation by wiring their
    // own WebAuthnManager through PasskeyAuthenticationServices.Builder.
    return webAuthnManager.verify(w4jRequest, w4jParams);
  }

  /**
   * Effective user-verification requirement for a finish step: {@code true} (UV required) if either
   * the global {@link CeremonyConfig#userVerification()} or the per-request requirement resolved at
   * start (persisted on {@link ChallengeRecord#userVerification()}) is {@code REQUIRED}, that is,
   * the stricter of the two. This enforces a per-request step-up {@code REQUIRED} server-side even
   * when the global default is relaxed to {@code PREFERRED}/{@code DISCOURAGED}, and never weakens
   * the global config. A {@code null} recorded requirement (legacy record) contributes nothing, so
   * the global config still applies.
   */
  private boolean effectiveUserVerificationRequired(ChallengeRecord challengeRecord) {
    boolean configRequired =
        WebAuthn4JConverters.userVerificationRequired(ceremonyConfig.userVerification());
    boolean perRequestRequired =
        challengeRecord.userVerification() != null
            && WebAuthn4JConverters.userVerificationRequired(challengeRecord.userVerification());
    return configRequired || perRequestRequired;
  }

  /** Outcome of {@link #evaluateAttestation(RegistrationData)}. */
  private sealed interface AttestationEvaluation {
    /** Registration may proceed to persistence with this verified credential data. */
    record Accepted(AttestedCredentialData attestedCredentialData)
        implements AttestationEvaluation {}

    /** Registration stops here with {@code result}. */
    record Rejected(RegistrationResult result) implements AttestationEvaluation {}
  }

  /**
   * Validates the attested credential data against the configured {@link AttestationTrustPolicy}
   * and rejects duplicates already stored.
   */
  private AttestationEvaluation evaluateAttestation(RegistrationData data) {
    AttestedCredentialData acd =
        data.getAttestationObject().getAuthenticatorData().getAttestedCredentialData();
    if (acd == null) {
      return new AttestationEvaluation.Rejected(
          new RegistrationResult.InvalidPayload("attested credential data missing"));
    }

    AttestationTrustPolicy.Decision policyDecision =
        attestationTrustPolicy.evaluate(
            new AttestationTrustPolicy.AttestationData(
                acd.getAaguid() == null ? null : acd.getAaguid().getValue(),
                data.getAttestationObject().getFormat(),
                ceremonyConfig.attestationConveyance()));
    if (policyDecision instanceof AttestationTrustPolicy.Decision.Rejected rej) {
      return new AttestationEvaluation.Rejected(
          new RegistrationResult.AttestationRejected(rej.reason()));
    }

    // Fast path only: a concurrent finish can insert the same id between this read and save().
    // The DuplicateCredentialException catch in persistRegistration is the authoritative check.
    CredentialId credentialId = CredentialId.of(acd.getCredentialId());
    if (credentialRepository.findByCredentialId(credentialId).isPresent()) {
      return new AttestationEvaluation.Rejected(
          new RegistrationResult.DuplicateCredential(credentialId));
    }
    return new AttestationEvaluation.Accepted(acd);
  }

  /**
   * Builds and saves the {@link CredentialRecord} for the just-verified registration and returns
   * the {@link RegistrationResult.Success} variant, or {@link
   * RegistrationResult.DuplicateCredential} when the repository reports the id already exists.
   */
  private RegistrationResult persistRegistration(
      FinishRegistrationRequest req,
      ChallengeRecord challengeRecord,
      RegistrationData data,
      AttestedCredentialData acd) {
    CredentialId credentialId = CredentialId.of(acd.getCredentialId());
    var authData = data.getAttestationObject().getAuthenticatorData();
    byte[] coseBytes = WebAuthn4JConverters.serializeCoseKey(acd.getCOSEKey(), objectConverter);
    // Null-guard the AAGUID to match evaluateAttestation: AAGUID.ZERO.equals(null) is false, so
    // without the explicit null check a null AAGUID would NPE on getValue() and escape as a 500
    // instead of a sealed RegistrationResult.
    UUID aaguidUuid =
        acd.getAaguid() == null || AAGUID.ZERO.equals(acd.getAaguid())
            ? null
            : acd.getAaguid().getValue();

    Set<Transport> transports = EnumSet.noneOf(Transport.class);
    if (data.getTransports() != null) {
      data.getTransports()
          .forEach(t -> Transport.fromWire(t.getValue()).ifPresent(transports::add));
    }

    Instant now = clockProvider.now();
    CredentialRecord newCredential =
        new CredentialRecord(
            credentialId,
            challengeRecord.userHandle() != null
                ? challengeRecord.userHandle()
                : userLookup.getOrCreateHandle(UserLookup.USERNAMELESS_KEY),
            coseBytes,
            authData.getSignCount(),
            labelOrDefault(req.label()),
            aaguidUuid,
            transports,
            authData.isFlagBE(),
            authData.isFlagBS(),
            now,
            null);
    try {
      credentialRepository.save(newCredential);
    } catch (DuplicateCredentialException ex) {
      // Lost a race with a concurrent finish for the same credential id after the pre-check.
      LOG.info(
          "registration.finish duplicate credential rejected on save credId={}",
          shortCredId(credentialId.value()));
      return new RegistrationResult.DuplicateCredential(credentialId);
    }

    AuthenticatorData ourAuthData =
        new AuthenticatorData(
            new byte[0],
            authData.isFlagUP(),
            authData.isFlagUV(),
            authData.isFlagBE(),
            authData.isFlagBS(),
            authData.isFlagAT(),
            authData.isFlagED(),
            authData.getSignCount());

    return new RegistrationResult.Success(newCredential, ourAuthData);
  }

  // -- Authentication --------------------------------------------------------------------------

  /**
   * Starts a passkey authentication ceremony.
   *
   * <p>Privacy invariant: {@code allowCredentials} on the returned options is always a (possibly
   * empty) list, never {@code null}. Emitting {@code null} for unknown usernames while emitting a
   * populated list for known users on this {@code permitAll} endpoint would create an
   * account-enumeration oracle. Mirrors the same privacy guard in {@code
   * MagicLinkService.startLogin}.
   *
   * @since 0.9.1
   */
  @Override
  public StartAuthenticationResult startAuthentication(
      StartAuthenticationRequest req, @Nullable String clientIp) {
    Objects.requireNonNull(req, "req");
    String deniedBucket = rateLimitedBucket("authentication.start", clientIp, req.username());
    if (deniedBucket != null) {
      return new StartAuthenticationResult.RateLimited(deniedBucket);
    }

    @Nullable UserHandle resolvedHandle = null;
    // Always non-null: unknown usernames and the usernameless flow both yield an empty list
    // rather than null so the wire shape is indistinguishable from a known user with no
    // credentials. Prevents account enumeration on the public start-authentication endpoint.
    List<PublicKeyCredentialDescriptor> allowCredentials = List.of();
    if (req.username() != null) {
      Optional<UserHandle> handle = userLookup.findHandleByUsername(req.username());
      if (handle.isPresent()) {
        resolvedHandle = handle.get();
        allowCredentials = descriptorsFor(resolvedHandle);
      }
    }

    IssuedChallenge issued =
        issueChallenge(
            ChallengeRecord.Purpose.AUTHENTICATION, resolvedHandle, req.userVerification());

    PublicKeyCredentialRequestOptionsJson options =
        new PublicKeyCredentialRequestOptionsJson(
            issued.challenge(),
            DEFAULT_TIMEOUT_MS,
            rpConfig.id(),
            allowCredentials,
            issued.userVerification(),
            null);

    metrics.incrementCounter("pkauth.authentication.start", "rp", rpConfig.id());
    LOG.info(
        "authentication.start username={} challengeId={}", req.username(), issued.id().value());
    return new StartAuthenticationResult.Started(
        new StartAuthenticationResponse(issued.id(), options));
  }

  @Override
  public AssertionResult finishAuthentication(
      FinishAuthenticationRequest req, @Nullable String clientIp) {
    Objects.requireNonNull(req, "req");
    long start = System.nanoTime();
    ChallengeValidator.Ceremony ceremony = ChallengeValidator.Ceremony.AUTHENTICATION;
    if (!rateLimiter.tryAcquireForIp(clientIp)) {
      LOG.info("authentication.finish rate-limited ip-bucket clientIp={}", clientIp);
      return emitOutcome(ceremony, new AssertionResult.RateLimited("ip"), start);
    }
    // Step 1: challenge / origin / ceremony-type preflight.
    ChallengeValidation validation =
        challengeValidator.validate(
            ceremony, req.challengeId(), req.response().response().clientDataJSON());
    if (!(validation instanceof ChallengeValidation.Valid valid)) {
      return emitOutcome(ceremony, mapAssertionPreflight(validation), start);
    }

    // Step 2: locate the credential and verify it belongs to the asserted user.
    CredentialRecord cred;
    switch (resolveCredential(req, valid.record())) {
      case CredentialResolution.Rejected rejected -> {
        return emitOutcome(ceremony, rejected.result(), start);
      }
      case CredentialResolution.Found found -> cred = found.credential();
    }

    // Step 3: WebAuthn4J cryptographic verification of the assertion. The stored COSE key is
    // decoded outside the try: a corrupt stored key is a server fault and must propagate, not be
    // misreported as a client error by the catch below (which covers client-controlled input only).
    var w4jCred = WebAuthn4JConverters.toW4jCredentialRecord(cred, objectConverter);
    AuthenticationData data;
    try {
      data = verifyAssertionWithW4j(req, valid.record(), w4jCred);
    } catch (DataConversionException | JacksonException | VerificationException ex) {
      return emitOutcome(ceremony, mapAssertionException(ex, cred, valid.clientData()), start);
    }

    // Step 4: persist the updated sign count and build the success result.
    return emitOutcome(ceremony, persistAssertion(cred, data), start);
  }

  /** Outcome of {@link #resolveCredential(FinishAuthenticationRequest, ChallengeRecord)}. */
  private sealed interface CredentialResolution {
    /** The asserted credential exists and is bound to the expected user. */
    record Found(CredentialRecord credential) implements CredentialResolution {}

    /** The assertion stops here with {@code result}. */
    record Rejected(AssertionResult.UnknownCredential result) implements CredentialResolution {}
  }

  /**
   * Parses the asserted credential id, looks up the stored record, and binds the assertion to the
   * start-time user handle (when present) and the response's user handle (when returned). Any
   * mismatch produces an {@link AssertionResult.UnknownCredential} so a wrong-owner credential
   * cannot be distinguished from a truly unknown one.
   */
  private CredentialResolution resolveCredential(
      FinishAuthenticationRequest req, ChallengeRecord challengeRecord) {
    byte[] credentialId = req.response().rawId();
    CredentialId credentialIdValue;
    try {
      credentialIdValue = CredentialId.of(credentialId);
    } catch (IllegalArgumentException ex) {
      // Empty rawId — substitute a sentinel CredentialId; wire response is still 404.
      return new CredentialResolution.Rejected(
          new AssertionResult.UnknownCredential(CredentialId.of(new byte[] {0})));
    }
    Optional<CredentialRecord> credOpt = credentialRepository.findByCredentialId(credentialIdValue);
    if (credOpt.isEmpty()) {
      return new CredentialResolution.Rejected(
          new AssertionResult.UnknownCredential(credentialIdValue));
    }
    CredentialRecord cred = credOpt.get();

    // Bind the asserted credential to the start-time user handle (if the start request named a
    // user) and to the WebAuthn response's userHandle (if the authenticator returned one), so a
    // valid credential belonging to another account cannot complete this user's ceremony.
    // The sealed AssertionResult hierarchy has no dedicated "credential mismatch" variant; treat
    // a wrong-owner credential as if it were unknown — same wire response, same metrics bucket.
    if (challengeRecord.userHandle() != null
        && !challengeRecord.userHandle().equals(cred.userHandle())) {
      LOG.warn(
          "authentication.finish credential userHandle does not match start-time userHandle"
              + " credId={}",
          shortCredId(credentialId));
      return new CredentialResolution.Rejected(
          new AssertionResult.UnknownCredential(credentialIdValue));
    }
    byte[] responseUserHandle = req.response().response().userHandle();
    if (responseUserHandle != null && responseUserHandle.length > 0) {
      UserHandle asserted;
      try {
        asserted = UserHandle.of(responseUserHandle);
      } catch (IllegalArgumentException ex) {
        // Malformed handle (wrong length) — treat as unknown credential rather than crash.
        return new CredentialResolution.Rejected(
            new AssertionResult.UnknownCredential(credentialIdValue));
      }
      if (!asserted.equals(cred.userHandle())) {
        LOG.warn(
            "authentication.finish response.userHandle does not match credential userHandle"
                + " credId={}",
            shortCredId(credentialId));
        return new CredentialResolution.Rejected(
            new AssertionResult.UnknownCredential(credentialIdValue));
      }
    }
    return new CredentialResolution.Found(cred);
  }

  /**
   * Hands the assertion response off to WebAuthn4J for cryptographic verification. Throws the
   * WebAuthn4J exception types the caller maps to specific result variants; programming errors
   * propagate.
   */
  private AuthenticationData verifyAssertionWithW4j(
      FinishAuthenticationRequest req,
      ChallengeRecord challengeRecord,
      com.webauthn4j.credential.CredentialRecord w4jCred) {
    var w4jRequest = WebAuthn4JConverters.toAuthenticationRequest(req.response());
    var serverProperty = WebAuthn4JConverters.serverProperty(rpConfig, challengeRecord.challenge());
    var w4jParams =
        new AuthenticationParameters(
            serverProperty,
            w4jCred,
            /* allowCredentials */ null,
            effectiveUserVerificationRequired(challengeRecord),
            /* userPresenceRequired */ true);
    return webAuthnManager.verify(w4jRequest, w4jParams);
  }

  /**
   * Persists the post-assertion sign-count update and returns the {@link AssertionResult.Success}
   * variant.
   */
  private AssertionResult persistAssertion(CredentialRecord cred, AuthenticationData data) {
    long newSignCount = data.getAuthenticatorData().getSignCount();
    credentialRepository.updateSignCount(cred.credentialId(), newSignCount, clockProvider.now());
    return new AssertionResult.Success(
        cred.userHandle(), cred.credentialId(), newSignCount, AssertionResult.CounterStatus.OK);
  }

  // -- Helpers ---------------------------------------------------------------------------------

  /** A freshly stored challenge: the opaque id, the bytes to sign, and the resolved UV policy. */
  private record IssuedChallenge(
      ChallengeId id, byte[] challenge, UserVerificationRequirement userVerification) {}

  /**
   * Generates a challenge, stores it under a fresh {@link ChallengeId} with the configured TTL, and
   * returns what the start response needs to echo back to the client.
   */
  private IssuedChallenge issueChallenge(
      ChallengeRecord.Purpose purpose,
      @Nullable UserHandle userHandle,
      @Nullable UserVerificationRequirement requestedUserVerification) {
    byte[] challenge = challengeGenerator.generate();
    ChallengeId challengeId = ChallengeId.random();

    // Resolve the user-verification requirement (per-request override, else ceremony default) and
    // persist it on the challenge record so the finish step can enforce it server-side. Without
    // this, a per-request REQUIRED (e.g. step-up) is advisory only — finish would fall back to the
    // global config and accept flagUV=false.
    UserVerificationRequirement uv =
        requestedUserVerification == null
            ? ceremonyConfig.userVerification()
            : requestedUserVerification;

    challengeStore.put(
        challengeId,
        new ChallengeRecord(
            challenge,
            purpose,
            userHandle,
            uv,
            clockProvider.now().plus(ceremonyConfig.challengeTtl())),
        ceremonyConfig.challengeTtl());
    return new IssuedChallenge(challengeId, challenge, uv);
  }

  /** The user's registered credentials as WebAuthn descriptors (never {@code null}). */
  private List<PublicKeyCredentialDescriptor> descriptorsFor(UserHandle userHandle) {
    return credentialRepository.findByUserHandle(userHandle).stream()
        .map(this::toDescriptor)
        .toList();
  }

  /** Translates a non-{@code Valid} {@link ChallengeValidation} into a registration result. */
  private RegistrationResult mapRegistrationPreflight(ChallengeValidation v) {
    return switch (v) {
      case ChallengeValidation.Valid ignored ->
          throw new IllegalStateException("mapRegistrationPreflight called on Valid");
      case ChallengeValidation.OriginMismatch o ->
          new RegistrationResult.OriginMismatch(rpConfig.origins().toString(), o.actual());
      case ChallengeValidation.MalformedClientData m ->
          new RegistrationResult.InvalidPayload(m.detail());
      case ChallengeValidation.CeremonyTypeMismatch t ->
          new RegistrationResult.InvalidPayload(t.detail());
      case ChallengeValidation.InvalidEncoding e ->
          new RegistrationResult.InvalidPayload(e.detail());
      case ChallengeValidation.MissingOrConsumed m ->
          new RegistrationResult.InvalidChallenge(m.detail());
      case ChallengeValidation.PurposeMismatch p ->
          new RegistrationResult.InvalidChallenge(p.detail());
      case ChallengeValidation.BytesMismatch b ->
          new RegistrationResult.InvalidChallenge(b.detail());
      case ChallengeValidation.Expired e -> new RegistrationResult.InvalidChallenge(e.detail());
    };
  }

  /**
   * Translates a non-{@code Valid} {@link ChallengeValidation} into an assertion result. {@link
   * AssertionResult} has no {@code InvalidPayload} variant, so malformed client data is reported as
   * {@code InvalidChallenge} too.
   */
  private AssertionResult mapAssertionPreflight(ChallengeValidation v) {
    return switch (v) {
      case ChallengeValidation.Valid ignored ->
          throw new IllegalStateException("mapAssertionPreflight called on Valid");
      case ChallengeValidation.OriginMismatch o ->
          new AssertionResult.OriginMismatch(rpConfig.origins().toString(), o.actual());
      case ChallengeValidation.MalformedClientData m ->
          new AssertionResult.InvalidChallenge(m.detail());
      case ChallengeValidation.CeremonyTypeMismatch t ->
          new AssertionResult.InvalidChallenge(t.detail());
      case ChallengeValidation.InvalidEncoding e ->
          new AssertionResult.InvalidChallenge(e.detail());
      case ChallengeValidation.MissingOrConsumed m ->
          new AssertionResult.InvalidChallenge(m.detail());
      case ChallengeValidation.PurposeMismatch p ->
          new AssertionResult.InvalidChallenge(p.detail());
      case ChallengeValidation.BytesMismatch b -> new AssertionResult.InvalidChallenge(b.detail());
      case ChallengeValidation.Expired e -> new AssertionResult.InvalidChallenge(e.detail());
    };
  }

  /**
   * Maps a WebAuthn4J registration failure. {@code ex} is one of the types caught around {@link
   * #verifyRegistrationWithW4j}: {@link DataConversionException}, {@link JacksonException}, or
   * {@link VerificationException}.
   */
  private RegistrationResult mapRegistrationException(
      RuntimeException ex, ClientDataJsonParser.ClientData clientData) {
    return switch (ex) {
      case DataConversionException e -> {
        LOG.debug("registration.finish DataConversionException", e);
        yield new RegistrationResult.InvalidPayload(messageOf(e));
      }
      case JacksonException e -> {
        // WebAuthn4J does not always wrap a malformed attestation-object CBOR payload in
        // DataConversionException — a structurally-broken object can surface a raw Jackson
        // (de)serialization error. Map it to InvalidPayload so attacker-controlled garbage yields
        // a clean 400, never an uncaught 500 across the sealed-result boundary.
        LOG.debug("registration.finish malformed attestation CBOR", e);
        yield new RegistrationResult.InvalidPayload("malformed attestation object");
      }
      case BadOriginException e ->
          new RegistrationResult.OriginMismatch(rpConfig.origins().toString(), clientData.origin());
      case BadChallengeException e -> new RegistrationResult.InvalidChallenge(messageOf(e));
      case MissingChallengeException e -> new RegistrationResult.InvalidChallenge(messageOf(e));
      // BadSignatureException needs no arm: the non-strict default manager does not verify
      // attestation signatures, and anything else WebAuthn4J rejects is a bad payload. Only the
      // types caught at the call site reach here; keep this switch in sync with that catch.
      default -> new RegistrationResult.InvalidPayload(messageOf(ex));
    };
  }

  /**
   * Maps a WebAuthn4J assertion failure. {@code ex} is one of the types caught around {@link
   * #verifyAssertionWithW4j}: {@link DataConversionException}, {@link JacksonException}, or {@link
   * VerificationException}.
   */
  private AssertionResult mapAssertionException(
      RuntimeException ex, CredentialRecord cred, ClientDataJsonParser.ClientData clientData) {
    return switch (ex) {
      // AssertionResult has no InvalidPayload variant; an undecodable assertion payload is reported
      // as InvalidChallenge, the closest client-error (400) variant.
      case DataConversionException e -> new AssertionResult.InvalidChallenge(messageOf(e));
      case JacksonException e -> {
        // Malformed authenticator-data extension CBOR surfaces as a raw Jackson error rather than a
        // DataConversionException (same gap the registration path guards against).
        LOG.debug("authentication.finish malformed authenticator data CBOR", e);
        yield new AssertionResult.InvalidChallenge("malformed authenticator data");
      }
      case MaliciousCounterValueException e -> counterRegression(cred, e.getPresentedCounter());
      case UserNotVerifiedException e -> new AssertionResult.UserVerificationRequired();
      case BadOriginException e ->
          new AssertionResult.OriginMismatch(rpConfig.origins().toString(), clientData.origin());
      case BadChallengeException e -> new AssertionResult.InvalidChallenge(messageOf(e));
      case MissingChallengeException e -> new AssertionResult.InvalidChallenge(messageOf(e));
      // UserNotPresentException, BadSignatureException, BadRpIdException, and every other
      // verification failure are reported uniformly as an invalid signature (401). Only the types
      // caught at the call site reach here; keep this switch in sync with that catch.
      default -> new AssertionResult.InvalidSignature();
    };
  }

  /**
   * Applies the configured {@link CounterRegressionPolicy}: {@code WARN} accepts the assertion
   * (without advancing the stored counter) and flags it {@code REGRESSED_WARN}; otherwise the
   * assertion fails with {@link AssertionResult.CounterRegression}.
   */
  private AssertionResult counterRegression(CredentialRecord cred, long received) {
    if (ceremonyConfig.counterRegression() == CounterRegressionPolicy.WARN) {
      LOG.warn(
          "authentication.counter-regression accepted stored={} received={} credId={}",
          cred.signCount(),
          received,
          shortCredId(cred.credentialId().value()));
      return new AssertionResult.Success(
          cred.userHandle(),
          cred.credentialId(),
          cred.signCount(),
          AssertionResult.CounterStatus.REGRESSED_WARN);
    }
    return new AssertionResult.CounterRegression(cred.signCount(), received);
  }

  private PublicKeyCredentialDescriptor toDescriptor(CredentialRecord cred) {
    return new PublicKeyCredentialDescriptor(
        "public-key", cred.credentialId().value(), transportWireNames(cred));
  }

  private static List<String> transportWireNames(CredentialRecord cred) {
    List<String> wire = new ArrayList<>(cred.transports().size());
    for (Transport t : cred.transports()) {
      wire.add(t.wireName());
    }
    return wire;
  }

  private String labelOrDefault(@Nullable String supplied) {
    return supplied == null || supplied.isBlank() ? "Passkey" : supplied;
  }

  private static String messageOf(Throwable t) {
    return t.getMessage() == null ? t.getClass().getSimpleName() : t.getMessage();
  }

  private static String shortCredId(byte[] credentialId) {
    int len = Math.min(8, credentialId.length);
    return HexFormat.of().formatHex(Arrays.copyOf(credentialId, len));
  }

  /**
   * Records the finish-ceremony outcome counter, duration timer, and summary log line for {@code
   * result}, then returns it unchanged.
   */
  private <R> R emitOutcome(ChallengeValidator.Ceremony ceremony, R result, long start) {
    Duration elapsed = Duration.ofNanos(System.nanoTime() - start);
    String tag = outcomeTag(result);
    metrics.incrementCounter(ceremony.outcomeCounterName(), "result", tag);
    metrics.recordTimer(ceremony.durationTimerName(), elapsed, "result", tag);
    LOG.info("{}.finish outcome={} latencyMs={}", ceremony.metricPhase(), tag, elapsed.toMillis());
    return result;
  }

  /**
   * The {@code result} metric tag: the result variant's simple name, except a counter-regression
   * accepted under {@link CounterRegressionPolicy#WARN}, which is tagged separately so it is not
   * counted as a clean success.
   */
  private static String outcomeTag(Object result) {
    if (result instanceof AssertionResult.Success s
        && s.counterStatus() == AssertionResult.CounterStatus.REGRESSED_WARN) {
      return COUNTER_REGRESSED_OUTCOME;
    }
    return result.getClass().getSimpleName();
  }

  /**
   * Consults the configured {@link CeremonyRateLimiter} for both the per-IP and per-username
   * buckets on a {@code start*} call. Returns the name of the bucket that denied the call ({@code
   * "ip"} or {@code "username"}), or {@code null} when both buckets allow it. The caller surfaces a
   * non-null result as the {@code RateLimited} variant of the relevant start-result sum, and must
   * do so before creating any challenge, so a throttled caller never touches the ChallengeStore.
   */
  private @Nullable String rateLimitedBucket(
      String phase, @Nullable String clientIp, @Nullable String username) {
    if (!rateLimiter.tryAcquireForIp(clientIp)) {
      LOG.info("{} rate-limited ip-bucket clientIp={}", phase, clientIp);
      return "ip";
    }
    // Case-fold before bucketing. UserLookup implementations resolve usernames case-insensitively
    // (DynamoDbUserLookup lower-cases the identity key), so keying the bucket on the raw request
    // string gave "alice", "Alice", and "ALICE" three independent budgets against one account — an
    // 8-character username yields 256 of them. The per-IP bucket does not compensate: the
    // per-username bucket exists precisely for the distributed case, which is the case the split
    // defeated. Folding here rather than inside the limiter means every CeremonyRateLimiter
    // implementation — including a host's shared Redis one — inherits the fix.
    if (username != null && !rateLimiter.tryAcquireForUsername(username.toLowerCase(Locale.ROOT))) {
      LOG.info("{} rate-limited username-bucket username={}", phase, username);
      return "username";
    }
    return null;
  }
}
