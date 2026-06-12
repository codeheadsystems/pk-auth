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
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResponse;
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
import com.codeheadsystems.pkauth.spi.CeremonyRateLimitedException;
import com.codeheadsystems.pkauth.spi.CeremonyRateLimiter;
import com.codeheadsystems.pkauth.spi.ChallengeRecord;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
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
import com.webauthn4j.verifier.exception.BadRpIdException;
import com.webauthn4j.verifier.exception.BadSignatureException;
import com.webauthn4j.verifier.exception.MaliciousCounterValueException;
import com.webauthn4j.verifier.exception.MissingChallengeException;
import com.webauthn4j.verifier.exception.UserNotPresentException;
import com.webauthn4j.verifier.exception.UserNotVerifiedException;
import com.webauthn4j.verifier.exception.VerificationException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.List;
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
 * <p>Construct via {@link com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationServices} (the
 * public factory in the {@code ceremony} package).
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
  private static final long DEFAULT_TIMEOUT_MS = 60_000L;

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
   * Backward-compatible constructor that wires a never-deny rate limiter. New call sites SHOULD use
   * {@link #DefaultPasskeyAuthenticationService(WebAuthnManager, ObjectConverter,
   * CredentialRepository, UserLookup, ChallengeStore, ClockProvider, OriginValidator,
   * AttestationTrustPolicy, RelyingPartyConfig, CeremonyConfig, ChallengeGenerator, Metrics,
   * CeremonyRateLimiter)} and pass an explicit limiter ({@code InMemoryCeremonyRateLimiter} for
   * single-instance hosts; a shared backend for multi-replica deployments).
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
      Metrics metrics) {
    this(
        webAuthnManager,
        objectConverter,
        credentialRepository,
        userLookup,
        challengeStore,
        clockProvider,
        originValidator,
        attestationTrustPolicy,
        rpConfig,
        ceremonyConfig,
        challengeGenerator,
        metrics,
        AllowAllRateLimiter.INSTANCE);
  }

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

  /**
   * Sentinel limiter used by the legacy no-rate-limiter constructor. Always allows — keeps existing
   * unit tests passing without forcing them to declare a limiter, while the adapter modules wire a
   * real {@link CeremonyRateLimiter} (defaulting to {@code InMemoryCeremonyRateLimiter}).
   */
  private enum AllowAllRateLimiter implements CeremonyRateLimiter {
    INSTANCE;

    @Override
    public boolean tryAcquireForIp(@Nullable String ip) {
      return true;
    }

    @Override
    public boolean tryAcquireForUsername(String username) {
      return true;
    }
  }

  // -- Registration ----------------------------------------------------------------------------

  /**
   * Starts a passkey registration ceremony.
   *
   * <p><strong>Privacy invariant:</strong> {@code excludeCredentials} on the returned options is
   * always a (possibly empty) list — never {@code null}. Emitting {@code null} for brand-new
   * usernames while emitting a populated list for existing users on this {@code permitAll} endpoint
   * would create an account-enumeration oracle. Mirrors the same privacy guard in {@code
   * MagicLinkService.startLogin}.
   *
   * @since 0.9.1
   */
  @Override
  public StartRegistrationResponse startRegistration(
      StartRegistrationRequest req, @Nullable String clientIp) {
    Objects.requireNonNull(req, "req");
    enforceRateLimit("registration.start", clientIp, req.username());
    UserHandle userHandle = userLookup.getOrCreateHandle(req.username());

    byte[] challenge = challengeGenerator.generate();
    ChallengeId challengeId = ChallengeId.random();

    challengeStore.put(
        challengeId,
        new ChallengeRecord(
            challenge,
            ChallengeRecord.Purpose.REGISTRATION,
            userHandle,
            clockProvider.now().plus(ceremonyConfig.challengeTtl())),
        ceremonyConfig.challengeTtl());

    // Always non-null: brand-new usernames yield an empty list rather than null so the wire
    // shape is indistinguishable from an existing user with no exclusions. Prevents account
    // enumeration on the public start-registration endpoint.
    List<PublicKeyCredentialDescriptor> excludeCredentials =
        credentialRepository.findByUserHandle(userHandle).stream().map(this::toDescriptor).toList();

    UserVerificationRequirement uv =
        req.userVerification() == null ? ceremonyConfig.userVerification() : req.userVerification();

    AuthenticatorSelectionCriteria selection =
        new AuthenticatorSelectionCriteria(null, ceremonyConfig.residentKey(), null, uv);

    PublicKeyCredentialCreationOptionsJson options =
        new PublicKeyCredentialCreationOptionsJson(
            new RelyingParty(rpConfig.id(), rpConfig.name()),
            new UserInfo(
                userHandle.value(),
                req.username(),
                req.displayName() == null ? req.username() : req.displayName()),
            challenge,
            List.of(
                new PublicKeyCredentialParameters("public-key", -7),
                new PublicKeyCredentialParameters("public-key", -8),
                new PublicKeyCredentialParameters("public-key", -257)),
            DEFAULT_TIMEOUT_MS,
            excludeCredentials,
            selection,
            ceremonyConfig.attestationConveyance(),
            null);

    metrics.incrementCounter("pkauth.registration.start", "rp", rpConfig.id());
    LOG.info("registration.start userHandle={} challengeId={}", userHandle, challengeId.value());
    return new StartRegistrationResponse(challengeId, options);
  }

  @Override
  public RegistrationResult finishRegistration(
      FinishRegistrationRequest req, @Nullable String clientIp) {
    Objects.requireNonNull(req, "req");
    long start = System.nanoTime();
    if (!rateLimiter.tryAcquireForIp(clientIp)) {
      LOG.info("registration.finish rate-limited ip-bucket clientIp={}", clientIp);
      return outcome(
          ChallengeValidator.Ceremony.REGISTRATION,
          new RegistrationResult.RateLimited("ip"),
          start);
    }
    // Step 1: challenge / origin / ceremony-type preflight.
    ChallengeValidation validation =
        challengeValidator.validate(
            ChallengeValidator.Ceremony.REGISTRATION,
            req.challengeId(),
            req.response().response().clientDataJSON());
    if (!(validation instanceof ChallengeValidation.Valid valid)) {
      return outcome(
          ChallengeValidator.Ceremony.REGISTRATION, mapRegistrationPreflight(validation), start);
    }

    // Step 2: WebAuthn4J cryptographic verification.
    RegistrationData data;
    try {
      data = verifyRegistrationWithW4j(req, valid.record());
    } catch (DataConversionException ex) {
      LOG.debug("registration.finish DataConversionException", ex);
      return outcome(
          ChallengeValidator.Ceremony.REGISTRATION,
          new RegistrationResult.InvalidPayload(messageOf(ex)),
          start);
    } catch (JacksonException ex) {
      // WebAuthn4J does not always wrap a malformed attestation-object CBOR payload in
      // DataConversionException — a structurally-broken object can surface a raw Jackson
      // (de)serialization error. Map it to InvalidPayload so attacker-controlled garbage yields a
      // clean 400, never an uncaught 500 across the sealed-result boundary.
      LOG.debug("registration.finish malformed attestation CBOR", ex);
      return outcome(
          ChallengeValidator.Ceremony.REGISTRATION,
          new RegistrationResult.InvalidPayload("malformed attestation object"),
          start);
    } catch (VerificationException ex) {
      return outcome(
          ChallengeValidator.Ceremony.REGISTRATION,
          mapRegistrationException(ex, valid.clientData()),
          start);
    }

    // Step 3: attestation policy + duplicate-credential check.
    RegistrationResult evaluation = evaluateAttestation(data);
    if (evaluation != null) {
      return outcome(ChallengeValidator.Ceremony.REGISTRATION, evaluation, start);
    }

    // Step 4: persist the new credential and build the success result.
    return outcome(
        ChallengeValidator.Ceremony.REGISTRATION,
        persistRegistration(req, valid.record(), data),
        start);
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
            WebAuthn4JConverters.DEFAULT_PUB_KEY_PARAMS,
            WebAuthn4JConverters.userVerificationRequired(ceremonyConfig.userVerification()),
            /* userPresenceRequired */ true);
    // Attestation signature verification is intentionally non-strict in the default manager;
    // BadSignatureException is not thrown here (see finding #41 / #3 for strict-mode opt-in).
    return webAuthnManager.verify(w4jRequest, w4jParams);
  }

  /**
   * Validates the attested credential data against the configured {@link AttestationTrustPolicy}
   * and rejects duplicates already stored. Returns the failure result to emit, or {@code null} when
   * the registration should proceed to persistence.
   */
  private @Nullable RegistrationResult evaluateAttestation(RegistrationData data) {
    AttestedCredentialData acd =
        data.getAttestationObject().getAuthenticatorData().getAttestedCredentialData();
    if (acd == null) {
      return new RegistrationResult.InvalidPayload("attested credential data missing");
    }

    AttestationTrustPolicy.Decision policyDecision =
        attestationTrustPolicy.evaluate(
            new AttestationTrustPolicy.AttestationData(
                acd.getAaguid() == null ? null : acd.getAaguid().getValue(),
                data.getAttestationObject().getFormat(),
                ceremonyConfig.attestationConveyance()));
    if (policyDecision instanceof AttestationTrustPolicy.Decision.Rejected rej) {
      return new RegistrationResult.AttestationRejected(rej.reason());
    }

    CredentialId acdCredentialId = CredentialId.of(acd.getCredentialId());
    if (credentialRepository.findByCredentialId(acdCredentialId).isPresent()) {
      return new RegistrationResult.DuplicateCredential(acdCredentialId);
    }
    return null;
  }

  /**
   * Builds and saves the {@link CredentialRecord} for the just-verified registration and returns
   * the {@link RegistrationResult.Success} variant.
   */
  private RegistrationResult persistRegistration(
      FinishRegistrationRequest req, ChallengeRecord challengeRecord, RegistrationData data) {
    AttestedCredentialData acd =
        data.getAttestationObject().getAuthenticatorData().getAttestedCredentialData();
    CredentialId acdCredentialId = CredentialId.of(acd.getCredentialId());

    var authData = data.getAttestationObject().getAuthenticatorData();
    byte[] coseBytes = WebAuthn4JConverters.serializeCoseKey(acd.getCOSEKey(), objectConverter);
    UUID aaguidUuid = AAGUID.ZERO.equals(acd.getAaguid()) ? null : acd.getAaguid().getValue();

    Set<Transport> transports = EnumSet.noneOf(Transport.class);
    if (data.getTransports() != null) {
      data.getTransports()
          .forEach(t -> Transport.fromWire(t.getValue()).ifPresent(transports::add));
    }

    Instant now = clockProvider.now();
    CredentialRecord stored2 =
        new CredentialRecord(
            acdCredentialId,
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
    credentialRepository.save(stored2);

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

    return new RegistrationResult.Success(stored2, ourAuthData);
  }

  // -- Authentication --------------------------------------------------------------------------

  /**
   * Starts a passkey authentication ceremony.
   *
   * <p><strong>Privacy invariant:</strong> {@code allowCredentials} on the returned options is
   * always a (possibly empty) list — never {@code null}. Emitting {@code null} for unknown
   * usernames while emitting a populated list for known users on this {@code permitAll} endpoint
   * would create an account-enumeration oracle. Mirrors the same privacy guard in {@code
   * MagicLinkService.startLogin}.
   *
   * @since 0.9.1
   */
  @Override
  public StartAuthenticationResponse startAuthentication(
      StartAuthenticationRequest req, @Nullable String clientIp) {
    Objects.requireNonNull(req, "req");
    enforceRateLimit("authentication.start", clientIp, req.username());

    @Nullable UserHandle resolvedHandle = null;
    // Always non-null: unknown usernames and the usernameless flow both yield an empty list
    // rather than null so the wire shape is indistinguishable from a known user with no
    // credentials. Prevents account enumeration on the public start-authentication endpoint.
    List<PublicKeyCredentialDescriptor> allowCredentials = List.of();
    if (req.username() != null) {
      Optional<UserHandle> handle = userLookup.findHandleByUsername(req.username());
      if (handle.isPresent()) {
        resolvedHandle = handle.get();
        allowCredentials =
            credentialRepository.findByUserHandle(resolvedHandle).stream()
                .map(this::toDescriptor)
                .toList();
      }
    }

    byte[] challenge = challengeGenerator.generate();
    ChallengeId challengeId = ChallengeId.random();

    challengeStore.put(
        challengeId,
        new ChallengeRecord(
            challenge,
            ChallengeRecord.Purpose.AUTHENTICATION,
            resolvedHandle,
            clockProvider.now().plus(ceremonyConfig.challengeTtl())),
        ceremonyConfig.challengeTtl());

    UserVerificationRequirement uv =
        req.userVerification() == null ? ceremonyConfig.userVerification() : req.userVerification();

    PublicKeyCredentialRequestOptionsJson options =
        new PublicKeyCredentialRequestOptionsJson(
            challenge, DEFAULT_TIMEOUT_MS, rpConfig.id(), allowCredentials, uv, null);

    metrics.incrementCounter("pkauth.authentication.start", "rp", rpConfig.id());
    LOG.info(
        "authentication.start username={} challengeId={}", req.username(), challengeId.value());
    return new StartAuthenticationResponse(challengeId, options);
  }

  @Override
  public AssertionResult finishAuthentication(
      FinishAuthenticationRequest req, @Nullable String clientIp) {
    Objects.requireNonNull(req, "req");
    long start = System.nanoTime();
    if (!rateLimiter.tryAcquireForIp(clientIp)) {
      LOG.info("authentication.finish rate-limited ip-bucket clientIp={}", clientIp);
      return outcomeAssertion(new AssertionResult.RateLimited("ip"), start);
    }
    // Step 1: challenge / origin / ceremony-type preflight.
    ChallengeValidation validation =
        challengeValidator.validate(
            ChallengeValidator.Ceremony.AUTHENTICATION,
            req.challengeId(),
            req.response().response().clientDataJSON());
    if (!(validation instanceof ChallengeValidation.Valid valid)) {
      return outcomeAssertion(mapAssertionPreflight(validation), start);
    }

    // Step 2: locate the credential and verify it belongs to the asserted user.
    CredentialResolution resolution = resolveCredential(req, valid.record());
    if (resolution.failure() != null) {
      return outcomeAssertion(resolution.failure(), start);
    }
    CredentialRecord cred = resolution.credential();
    CredentialId credentialId = CredentialId.of(req.response().rawId());

    // Step 3: WebAuthn4J cryptographic verification of the assertion.
    AuthenticationData data;
    try {
      data = verifyAssertionWithW4j(req, valid.record(), cred);
    } catch (DataConversionException ex) {
      return outcomeAssertion(new AssertionResult.InvalidChallenge(messageOf(ex)), start);
    } catch (MaliciousCounterValueException ex) {
      return handleCounterRegression(cred, ex.getPresentedCounter(), start);
    } catch (UserNotVerifiedException ex) {
      return outcomeAssertion(new AssertionResult.UserVerificationRequired(), start);
    } catch (UserNotPresentException ex) {
      return outcomeAssertion(new AssertionResult.InvalidSignature(), start);
    } catch (BadSignatureException ex) {
      return outcomeAssertion(new AssertionResult.InvalidSignature(), start);
    } catch (BadOriginException ex) {
      return outcomeAssertion(
          new AssertionResult.OriginMismatch(
              rpConfig.origins().toString(), valid.clientData().origin()),
          start);
    } catch (BadChallengeException | MissingChallengeException ex) {
      return outcomeAssertion(new AssertionResult.InvalidChallenge(messageOf(ex)), start);
    } catch (BadRpIdException ex) {
      return outcomeAssertion(new AssertionResult.InvalidSignature(), start);
    } catch (VerificationException ex) {
      return outcomeAssertion(new AssertionResult.InvalidSignature(), start);
    }

    // Step 4: persist the updated sign count and build the success result.
    return outcomeAssertion(persistAssertion(cred, credentialId, data), start);
  }

  /**
   * Holds the outcome of {@link #resolveCredential(FinishAuthenticationRequest, ChallengeRecord)}.
   * Exactly one of {@code credential} / {@code failure} is non-null.
   */
  private record CredentialResolution(
      @Nullable CredentialRecord credential, @Nullable AssertionResult failure) {
    static CredentialResolution success(CredentialRecord cred) {
      return new CredentialResolution(cred, null);
    }

    static CredentialResolution failed(AssertionResult result) {
      return new CredentialResolution(null, result);
    }
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
      return CredentialResolution.failed(
          new AssertionResult.UnknownCredential(CredentialId.of(new byte[] {0})));
    }
    Optional<CredentialRecord> credOpt = credentialRepository.findByCredentialId(credentialIdValue);
    if (credOpt.isEmpty()) {
      return CredentialResolution.failed(new AssertionResult.UnknownCredential(credentialIdValue));
    }
    CredentialRecord cred = credOpt.get();

    // Fix #18: bind the asserted credential to the start-time user handle (if the start request
    // named a user) and to the WebAuthn response's userHandle (if the authenticator returned one).
    // The sealed AssertionResult hierarchy has no dedicated "credential mismatch" variant; treat
    // a wrong-owner credential as if it were unknown — same wire response, same metrics bucket.
    if (challengeRecord.userHandle() != null
        && !challengeRecord.userHandle().equals(cred.userHandle())) {
      LOG.warn(
          "authentication.finish credential userHandle does not match start-time userHandle"
              + " credId={}",
          shortCredId(credentialId));
      return CredentialResolution.failed(new AssertionResult.UnknownCredential(credentialIdValue));
    }
    byte[] responseUserHandle = req.response().response().userHandle();
    if (responseUserHandle != null && responseUserHandle.length > 0) {
      UserHandle asserted;
      try {
        asserted = UserHandle.of(responseUserHandle);
      } catch (IllegalArgumentException ex) {
        // Malformed handle (wrong length) — treat as unknown credential rather than crash.
        return CredentialResolution.failed(
            new AssertionResult.UnknownCredential(credentialIdValue));
      }
      if (!asserted.equals(cred.userHandle())) {
        LOG.warn(
            "authentication.finish response.userHandle does not match credential userHandle"
                + " credId={}",
            shortCredId(credentialId));
        return CredentialResolution.failed(
            new AssertionResult.UnknownCredential(credentialIdValue));
      }
    }
    return CredentialResolution.success(cred);
  }

  /**
   * Hands the assertion response off to WebAuthn4J for cryptographic verification. Throws the
   * WebAuthn4J exception types the caller maps to specific result variants; programming errors
   * propagate.
   */
  private AuthenticationData verifyAssertionWithW4j(
      FinishAuthenticationRequest req, ChallengeRecord challengeRecord, CredentialRecord cred) {
    var w4jRequest = WebAuthn4JConverters.toAuthenticationRequest(req.response());
    var serverProperty = WebAuthn4JConverters.serverProperty(rpConfig, challengeRecord.challenge());
    var w4jCred = WebAuthn4JConverters.toW4jCredentialRecord(cred, objectConverter);
    var w4jParams =
        new AuthenticationParameters(
            serverProperty,
            w4jCred,
            /* allowCredentials */ null,
            WebAuthn4JConverters.userVerificationRequired(ceremonyConfig.userVerification()),
            /* userPresenceRequired */ true);
    return webAuthnManager.verify(w4jRequest, w4jParams);
  }

  /**
   * Persists the post-assertion sign-count update and returns the {@link AssertionResult.Success}
   * variant.
   */
  private AssertionResult persistAssertion(
      CredentialRecord cred, CredentialId credentialId, AuthenticationData data) {
    long newSignCount = data.getAuthenticatorData().getSignCount();
    credentialRepository.updateSignCount(cred.credentialId(), newSignCount, clockProvider.now());
    return new AssertionResult.Success(
        cred.userHandle(), credentialId, newSignCount, AssertionResult.CounterStatus.OK);
  }

  // -- Helpers ---------------------------------------------------------------------------------

  /**
   * Translates a {@link ChallengeValidation} non-{@code Valid} variant into a registration result.
   */
  private RegistrationResult mapRegistrationPreflight(ChallengeValidation v) {
    return ChallengeValidation.toResult(
        v,
        new ChallengeValidation.Mapper<RegistrationResult>() {
          @Override
          public RegistrationResult malformedClientData(String detail) {
            return new RegistrationResult.InvalidPayload(detail);
          }

          @Override
          public RegistrationResult ceremonyTypeMismatch(String expected, String actual) {
            return new RegistrationResult.InvalidPayload("clientData.type must be " + expected);
          }

          @Override
          public RegistrationResult originMismatch(String actual) {
            return new RegistrationResult.OriginMismatch(rpConfig.origins().toString(), actual);
          }

          @Override
          public RegistrationResult invalidEncoding(String detail) {
            return new RegistrationResult.InvalidPayload(detail);
          }

          @Override
          public RegistrationResult missingOrConsumed() {
            return new RegistrationResult.InvalidChallenge(
                "unknown, expired, or already-consumed challenge");
          }

          @Override
          public RegistrationResult purposeMismatch() {
            return new RegistrationResult.InvalidChallenge(
                "challenge bound to a different ceremony");
          }

          @Override
          public RegistrationResult bytesMismatch() {
            return new RegistrationResult.InvalidChallenge(
                "challenge bytes do not match stored value");
          }

          @Override
          public RegistrationResult expired() {
            return new RegistrationResult.InvalidChallenge("challenge expired");
          }
        });
  }

  /**
   * Translates a {@link ChallengeValidation} non-{@code Valid} variant into an assertion result.
   */
  private AssertionResult mapAssertionPreflight(ChallengeValidation v) {
    return ChallengeValidation.toResult(
        v,
        new ChallengeValidation.Mapper<AssertionResult>() {
          @Override
          public AssertionResult malformedClientData(String detail) {
            return new AssertionResult.InvalidChallenge(detail);
          }

          @Override
          public AssertionResult ceremonyTypeMismatch(String expected, String actual) {
            return new AssertionResult.InvalidChallenge("clientData.type must be " + expected);
          }

          @Override
          public AssertionResult originMismatch(String actual) {
            return new AssertionResult.OriginMismatch(rpConfig.origins().toString(), actual);
          }

          @Override
          public AssertionResult invalidEncoding(String detail) {
            return new AssertionResult.InvalidChallenge(detail);
          }

          @Override
          public AssertionResult missingOrConsumed() {
            return new AssertionResult.InvalidChallenge(
                "unknown, expired, or already-consumed challenge");
          }

          @Override
          public AssertionResult purposeMismatch() {
            return new AssertionResult.InvalidChallenge("challenge bound to a different ceremony");
          }

          @Override
          public AssertionResult bytesMismatch() {
            return new AssertionResult.InvalidChallenge(
                "challenge bytes do not match stored value");
          }

          @Override
          public AssertionResult expired() {
            return new AssertionResult.InvalidChallenge("challenge expired");
          }
        });
  }

  private AssertionResult handleCounterRegression(
      CredentialRecord cred, long received, long start) {
    if (ceremonyConfig.counterRegression() == CounterRegressionPolicy.WARN) {
      LOG.warn(
          "authentication.counter-regression accepted stored={} received={} credId={}",
          cred.signCount(),
          received,
          shortCredId(cred.credentialId().value()));
      Duration elapsed = Duration.ofNanos(System.nanoTime() - start);
      ChallengeValidator.Ceremony ceremony = ChallengeValidator.Ceremony.AUTHENTICATION;
      metrics.incrementCounter(
          ceremony.outcomeCounterName(), "result", "success_counter_regressed");
      metrics.recordTimer(
          ceremony.durationTimerName(), elapsed, "result", "success_counter_regressed");
      LOG.info(
          "authentication.finish outcome=success_counter_regressed latencyMs={}",
          elapsed.toMillis());
      return new AssertionResult.Success(
          cred.userHandle(),
          cred.credentialId(),
          cred.signCount(),
          AssertionResult.CounterStatus.REGRESSED_WARN);
    }
    return outcomeAssertion(
        new AssertionResult.CounterRegression(cred.signCount(), received), start);
  }

  private RegistrationResult mapRegistrationException(
      VerificationException ex, ClientDataJsonParser.ClientData clientData) {
    if (ex instanceof BadOriginException) {
      return new RegistrationResult.OriginMismatch(
          rpConfig.origins().toString(), clientData.origin());
    }
    if (ex instanceof BadChallengeException || ex instanceof MissingChallengeException) {
      return new RegistrationResult.InvalidChallenge(messageOf(ex));
    }
    // BadSignatureException omitted: the non-strict default manager does not throw it (#41 / #3).
    return new RegistrationResult.InvalidPayload(messageOf(ex));
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

  private RegistrationResult outcome(
      ChallengeValidator.Ceremony ceremony, RegistrationResult result, long start) {
    Duration elapsed = Duration.ofNanos(System.nanoTime() - start);
    String variant = result.getClass().getSimpleName();
    metrics.incrementCounter(ceremony.outcomeCounterName(), "result", variant);
    metrics.recordTimer(ceremony.durationTimerName(), elapsed, "result", variant);
    LOG.info(
        "{}.finish outcome={} latencyMs={}", ceremony.metricPhase(), variant, elapsed.toMillis());
    return result;
  }

  private AssertionResult outcomeAssertion(AssertionResult result, long start) {
    Duration elapsed = Duration.ofNanos(System.nanoTime() - start);
    String variant = result.getClass().getSimpleName();
    ChallengeValidator.Ceremony ceremony = ChallengeValidator.Ceremony.AUTHENTICATION;
    metrics.incrementCounter(ceremony.outcomeCounterName(), "result", variant);
    metrics.recordTimer(ceremony.durationTimerName(), elapsed, "result", variant);
    LOG.info(
        "{}.finish outcome={} latencyMs={}", ceremony.metricPhase(), variant, elapsed.toMillis());
    return result;
  }

  /**
   * Consults the configured {@link CeremonyRateLimiter} for both the per-IP and per-username
   * buckets on a {@code start*} call. Throws {@link CeremonyRateLimitedException} when either
   * bucket denies; the adapter controller catches this and emits {@code 429 Too Many Requests}.
   */
  private void enforceRateLimit(
      String phase, @Nullable String clientIp, @Nullable String username) {
    if (!rateLimiter.tryAcquireForIp(clientIp)) {
      LOG.info("{} rate-limited ip-bucket clientIp={}", phase, clientIp);
      throw new CeremonyRateLimitedException("ip");
    }
    if (username != null && !rateLimiter.tryAcquireForUsername(username)) {
      LOG.info("{} rate-limited username-bucket username={}", phase, username);
      throw new CeremonyRateLimitedException("username");
    }
  }
}
