// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.codeheadsystems.pkauth.api.AttestationConveyance;
import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson.AuthenticatorAttestationResponseJson;
import com.codeheadsystems.pkauth.api.RegistrationResult;
import com.codeheadsystems.pkauth.api.ResidentKeyRequirement;
import com.codeheadsystems.pkauth.api.Transport;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.api.UserVerificationRequirement;
import com.codeheadsystems.pkauth.config.CeremonyConfig;
import com.codeheadsystems.pkauth.config.CounterRegressionPolicy;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.metrics.Metrics;
import com.codeheadsystems.pkauth.spi.AttestationTrustPolicy;
import com.codeheadsystems.pkauth.spi.ChallengeRecord;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.OriginValidator;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

/**
 * Happy-path registration ({@code persistRegistration}) and the {@code evaluateAttestation}
 * decision branches, which the main service test doesn't reach because it never returns a verified
 * {@link RegistrationData} from the mocked {@link WebAuthnManager}.
 */
class DefaultPasskeyAuthenticationServiceRegistrationTest {

  private static final Instant NOW = Instant.parse("2026-05-13T12:00:00Z");
  private static final byte[] CHALLENGE = filled(32, (byte) 1);
  private static final ChallengeId CHALLENGE_ID = new ChallengeId(Base64Url.encode(CHALLENGE));
  private static final UserHandle USER_HANDLE = UserHandle.of(filled(16, (byte) 9));
  private static final byte[] CRED_ID = filled(20, (byte) 2);
  private static final CredentialId CRED_ID_VALUE = CredentialId.of(CRED_ID);

  private final JsonMapper jsonMapper =
      JsonMapper.builder()
          .changeDefaultPropertyInclusion(v -> v.withValueInclusion(JsonInclude.Include.NON_NULL))
          .build();
  private final ObjectConverter objectConverter = new ObjectConverter();

  private WebAuthnManager webAuthnManager;
  private CredentialRepository credentialRepository;
  private UserLookup userLookup;
  private ChallengeStore challengeStore;
  private OriginValidator originValidator;
  private AttestationTrustPolicy attestationTrustPolicy;
  private Metrics metrics;
  private DefaultPasskeyAuthenticationService service;

  @BeforeEach
  void setUp() {
    webAuthnManager = mock(WebAuthnManager.class);
    credentialRepository = mock(CredentialRepository.class);
    userLookup = mock(UserLookup.class);
    challengeStore = mock(ChallengeStore.class);
    originValidator = mock(OriginValidator.class);
    attestationTrustPolicy = mock(AttestationTrustPolicy.class);
    metrics = mock(Metrics.class);

    lenient().when(originValidator.isAllowed("https://example.com")).thenReturn(true);
    lenient()
        .when(attestationTrustPolicy.evaluate(any()))
        .thenReturn(new AttestationTrustPolicy.Decision.Trusted());
    // Default: challenge present + valid for registration, and the credential is brand new.
    lenient()
        .when(challengeStore.takeOnce(CHALLENGE_ID))
        .thenReturn(
            Optional.of(
                new ChallengeRecord(
                    CHALLENGE,
                    ChallengeRecord.Purpose.REGISTRATION,
                    USER_HANDLE,
                    NOW.plusSeconds(300))));
    lenient()
        .when(credentialRepository.findByCredentialId(CRED_ID_VALUE))
        .thenReturn(Optional.empty());

    RelyingPartyConfig rp =
        new RelyingPartyConfig("example.com", "Example", Set.of("https://example.com"));
    CeremonyConfig ceremonyConfig =
        new CeremonyConfig(
            Duration.ofMinutes(5),
            UserVerificationRequirement.PREFERRED,
            ResidentKeyRequirement.PREFERRED,
            AttestationConveyance.NONE,
            CounterRegressionPolicy.REJECT);
    SecureRandom random =
        new SecureRandom() {
          @Override
          public void nextBytes(byte[] bytes) {
            System.arraycopy(CHALLENGE, 0, bytes, 0, Math.min(bytes.length, CHALLENGE.length));
          }
        };
    service =
        new DefaultPasskeyAuthenticationService(
            webAuthnManager,
            objectConverter,
            credentialRepository,
            userLookup,
            challengeStore,
            ClockProvider.fromClock(Clock.fixed(NOW, ZoneOffset.UTC)),
            originValidator,
            attestationTrustPolicy,
            rp,
            ceremonyConfig,
            new ChallengeGenerator(random),
            metrics);
  }

  @Test
  void happyPathPersistsCredentialWithTransportsAndAaguidAndLabel() throws Exception {
    UUID aaguid = UUID.fromString("01020304-0506-0708-090a-0b0c0d0e0f10");
    RegistrationData regData =
        mockRegistrationData(new AAGUID(aaguid), Set.of(AuthenticatorTransport.USB), false);
    when(webAuthnManager.verify(
            any(com.webauthn4j.data.RegistrationRequest.class), any(RegistrationParameters.class)))
        .thenReturn(regData);

    RegistrationResult result = service.finishRegistration(finishReg(cd(), "My Key"));

    assertThat(result)
        .isInstanceOfSatisfying(
            RegistrationResult.Success.class,
            s -> {
              assertThat(s.credential().credentialId()).isEqualTo(CRED_ID_VALUE);
              assertThat(s.credential().userHandle()).isEqualTo(USER_HANDLE);
              assertThat(s.credential().label()).isEqualTo("My Key");
              assertThat(s.credential().aaguid()).isEqualTo(aaguid);
              assertThat(s.credential().transports()).contains(Transport.USB);
              assertThat(s.credential().createdAt()).isEqualTo(NOW);
            });

    var captor = org.mockito.ArgumentCaptor.forClass(CredentialRecord.class);
    verify(credentialRepository).save(captor.capture());
    assertThat(captor.getValue().credentialId()).isEqualTo(CRED_ID_VALUE);
    verify(metrics).incrementCounter("pkauth.registration.outcome", "result", "Success");
  }

  @Test
  void happyPathWithZeroAaguidNullTransportsAndDefaultLabel() throws Exception {
    // AAGUID.ZERO → stored aaguid is null; null transports → empty transport set; null label →
    // "Passkey" default.
    RegistrationData regData = mockRegistrationData(AAGUID.ZERO, null, false);
    when(webAuthnManager.verify(
            any(com.webauthn4j.data.RegistrationRequest.class), any(RegistrationParameters.class)))
        .thenReturn(regData);

    RegistrationResult result = service.finishRegistration(finishReg(cd(), null));

    assertThat(result)
        .isInstanceOfSatisfying(
            RegistrationResult.Success.class,
            s -> {
              assertThat(s.credential().aaguid()).isNull();
              assertThat(s.credential().transports()).isEmpty();
              assertThat(s.credential().label()).isEqualTo("Passkey");
            });
  }

  @Test
  void usernamelessChallengeFallsBackToUsernamelessHandle() throws Exception {
    UserHandle usernameless = UserHandle.of(filled(16, (byte) 7));
    when(challengeStore.takeOnce(CHALLENGE_ID))
        .thenReturn(
            Optional.of(
                new ChallengeRecord(
                    CHALLENGE, ChallengeRecord.Purpose.REGISTRATION, null, NOW.plusSeconds(300))));
    when(userLookup.getOrCreateHandle(UserLookup.USERNAMELESS_KEY)).thenReturn(usernameless);
    RegistrationData regData = mockRegistrationData(AAGUID.ZERO, null, false);
    when(webAuthnManager.verify(
            any(com.webauthn4j.data.RegistrationRequest.class), any(RegistrationParameters.class)))
        .thenReturn(regData);

    RegistrationResult result = service.finishRegistration(finishReg(cd(), "k"));
    assertThat(result)
        .isInstanceOfSatisfying(
            RegistrationResult.Success.class,
            s -> assertThat(s.credential().userHandle()).isEqualTo(usernameless));
  }

  @Test
  void missingAttestedCredentialDataIsInvalidPayload() throws Exception {
    RegistrationData regData = mockRegistrationData(AAGUID.ZERO, null, /* acdNull */ true);
    when(webAuthnManager.verify(
            any(com.webauthn4j.data.RegistrationRequest.class), any(RegistrationParameters.class)))
        .thenReturn(regData);

    RegistrationResult result = service.finishRegistration(finishReg(cd(), "k"));
    assertThat(result)
        .isInstanceOfSatisfying(
            RegistrationResult.InvalidPayload.class,
            p -> assertThat(p.detail()).contains("attested credential data missing"));
    verify(credentialRepository, never()).save(any());
  }

  @Test
  void rejectedAttestationPolicyYieldsAttestationRejected() throws Exception {
    when(attestationTrustPolicy.evaluate(any()))
        .thenReturn(new AttestationTrustPolicy.Decision.Rejected("untrusted authenticator"));
    RegistrationData regData = mockRegistrationData(AAGUID.ZERO, null, false);
    when(webAuthnManager.verify(
            any(com.webauthn4j.data.RegistrationRequest.class), any(RegistrationParameters.class)))
        .thenReturn(regData);

    RegistrationResult result = service.finishRegistration(finishReg(cd(), "k"));
    assertThat(result)
        .isInstanceOfSatisfying(
            RegistrationResult.AttestationRejected.class,
            r -> assertThat(r.reason()).isEqualTo("untrusted authenticator"));
    verify(credentialRepository, never()).save(any());
  }

  @Test
  void duplicateCredentialIsRejectedBeforePersist() throws Exception {
    when(credentialRepository.findByCredentialId(CRED_ID_VALUE))
        .thenReturn(Optional.of(mock(CredentialRecord.class)));
    RegistrationData regData = mockRegistrationData(AAGUID.ZERO, null, false);
    when(webAuthnManager.verify(
            any(com.webauthn4j.data.RegistrationRequest.class), any(RegistrationParameters.class)))
        .thenReturn(regData);

    RegistrationResult result = service.finishRegistration(finishReg(cd(), "k"));
    assertThat(result)
        .isInstanceOfSatisfying(
            RegistrationResult.DuplicateCredential.class,
            d -> assertThat(d.credentialId()).isEqualTo(CRED_ID_VALUE));
    verify(credentialRepository, never()).save(any());
  }

  @Test
  void missingChallengeVerificationExceptionMapsToInvalidChallenge() throws Exception {
    when(webAuthnManager.verify(
            any(com.webauthn4j.data.RegistrationRequest.class), any(RegistrationParameters.class)))
        .thenThrow(new com.webauthn4j.verifier.exception.MissingChallengeException("missing"));

    RegistrationResult result = service.finishRegistration(finishReg(cd(), "k"));
    assertThat(result).isInstanceOf(RegistrationResult.InvalidChallenge.class);
  }

  // -- fixtures -----------------------------------------------------------------------------

  private RegistrationData mockRegistrationData(
      AAGUID aaguid, Set<AuthenticatorTransport> transports, boolean acdNull) {
    RegistrationData data = mock(RegistrationData.class);
    AttestationObject ao = mock(AttestationObject.class);
    @SuppressWarnings("unchecked")
    com.webauthn4j.data.attestation.authenticator.AuthenticatorData<
            com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput>
        authData = mock(com.webauthn4j.data.attestation.authenticator.AuthenticatorData.class);
    when(data.getAttestationObject()).thenReturn(ao);
    when(ao.getAuthenticatorData()).thenAnswer(inv -> authData);
    when(ao.getFormat()).thenReturn("none");
    when(data.getTransports()).thenReturn(transports);

    if (acdNull) {
      when(authData.getAttestedCredentialData()).thenReturn(null);
      return data;
    }

    AttestedCredentialData acd = mock(AttestedCredentialData.class);
    when(authData.getAttestedCredentialData()).thenReturn(acd);
    when(acd.getCredentialId()).thenReturn(CRED_ID);
    when(acd.getAaguid()).thenReturn(aaguid);
    when(acd.getCOSEKey()).thenAnswer(inv -> coseKey());
    when(authData.getSignCount()).thenReturn(0L);
    when(authData.isFlagUP()).thenReturn(true);
    when(authData.isFlagUV()).thenReturn(true);
    when(authData.isFlagBE()).thenReturn(false);
    when(authData.isFlagBS()).thenReturn(false);
    when(authData.isFlagAT()).thenReturn(true);
    when(authData.isFlagED()).thenReturn(false);
    return data;
  }

  private static EC2COSEKey coseKey() {
    byte[] point = new byte[65];
    point[0] = 0x04;
    for (int i = 1; i < point.length; i++) {
      point[i] = (byte) i;
    }
    return EC2COSEKey.createFromUncompressedECCKey(point);
  }

  private FinishRegistrationRequest finishReg(byte[] clientDataJson, String label) {
    return new FinishRegistrationRequest(
        CHALLENGE_ID,
        "alice",
        label,
        new RegistrationResponseJson(
            CRED_ID,
            CRED_ID,
            new AuthenticatorAttestationResponseJson(
                clientDataJson, new byte[] {(byte) 0xa0}, null, null, null, null),
            null,
            null,
            "public-key"));
  }

  private byte[] cd() {
    var node = jsonMapper.createObjectNode();
    node.put("type", "webauthn.create");
    node.put("challenge", Base64Url.encode(CHALLENGE));
    node.put("origin", "https://example.com");
    return jsonMapper.writeValueAsString(node).getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] filled(int len, byte v) {
    byte[] out = new byte[len];
    java.util.Arrays.fill(out, v);
    return out;
  }
}
