// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson.AuthenticatorAttestationResponseJson;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResult;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.config.CeremonyConfig;
import com.codeheadsystems.pkauth.config.CoseAlgorithm;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
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
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import tools.jackson.databind.json.JsonMapper;

/**
 * Verifies that the COSE algorithm lists flow from {@link CeremonyConfig} into both the
 * create-options ceremony (offered) and the WebAuthn4J verify path (accepted) — the single source
 * of truth introduced for crypto-agility / post-quantum readiness (ADR 0019).
 */
class DefaultPasskeyAuthenticationServiceAlgorithmTest {

  private static final Instant NOW = Instant.parse("2026-05-13T12:00:00Z");
  private static final byte[] CHALLENGE = filled(32, (byte) 1);
  private static final ChallengeId CHALLENGE_ID = new ChallengeId(Base64Url.encode(CHALLENGE));
  private static final UserHandle USER_HANDLE = UserHandle.of(filled(16, (byte) 9));
  private static final byte[] CRED_ID = filled(20, (byte) 2);

  private final JsonMapper jsonMapper =
      JsonMapper.builder()
          .changeDefaultPropertyInclusion(v -> v.withValueInclusion(JsonInclude.Include.NON_NULL))
          .build();
  private final ObjectConverter objectConverter = new ObjectConverter();

  @Test
  void defaultConfigOffersAndAcceptsHistoricalAlgorithms() {
    Harness h = new Harness(CeremonyConfig.defaults());

    // (a) create-options still offers ES256, EdDSA, RS256.
    assertThat(offeredAlgs(h)).containsExactly(-7L, -8L, -257L);

    // (a) verify still accepts ES256, EdDSA, RS256, ES384, RS384 (the historical union).
    assertThat(acceptedAlgs(h)).containsExactly(-7L, -8L, -257L, -35L, -258L);
  }

  @Test
  void customConfigFlowsIntoBothCreateOptionsAndVerifyParams() {
    // (b) a narrower offered list and a custom accepted list (offered must be a subset).
    CeremonyConfig custom =
        CeremonyConfig.from(
            null,
            null,
            null,
            null,
            null,
            List.of(CoseAlgorithm.ES256),
            List.of(CoseAlgorithm.ES256, CoseAlgorithm.ES384));
    Harness h = new Harness(custom);

    assertThat(offeredAlgs(h)).containsExactly(-7L);
    assertThat(acceptedAlgs(h)).containsExactly(-7L, -35L);
  }

  @Test
  void algorithmAbsentFromConfigIsNotOfferedToTheVerifier() {
    // (c) RS256 absent from the accepted list → it is not in the WebAuthn4J pubKeyCredParams, so
    // WebAuthn4J rejects any registration whose COSE key uses RS256. We assert the exclusion at the
    // parameter boundary (WebAuthn4J performs the actual rejection against this list).
    CeremonyConfig noRs256 =
        CeremonyConfig.from(
            null,
            null,
            null,
            null,
            null,
            List.of(CoseAlgorithm.ES256),
            List.of(CoseAlgorithm.ES256, CoseAlgorithm.EdDSA));
    Harness h = new Harness(noRs256);

    assertThat(acceptedAlgs(h)).containsExactly(-7L, -8L).doesNotContain(-257L);
  }

  /** Offered COSE algorithm identifiers from the create-options ceremony. */
  private List<Long> offeredAlgs(Harness h) {
    StartRegistrationResult result =
        h.service.startRegistration(
            new StartRegistrationRequest("alice", "Alice", null, null), null);
    assertThat(result).isInstanceOf(StartRegistrationResult.Started.class);
    return ((StartRegistrationResult.Started) result)
        .response().publicKey().pubKeyCredParams().stream().map(p -> p.alg()).toList();
  }

  /** Accepted COSE algorithm identifiers as passed to WebAuthn4J on the finish/verify path. */
  private List<Long> acceptedAlgs(Harness h) {
    // The mocked manager throws after the argument is captured; we only care about the parameters.
    when(h.webAuthnManager.verify(
            any(com.webauthn4j.data.RegistrationRequest.class), any(RegistrationParameters.class)))
        .thenThrow(new com.webauthn4j.verifier.exception.MissingChallengeException("ignored"));

    h.service.finishRegistration(finishReg());

    ArgumentCaptor<RegistrationParameters> captor =
        ArgumentCaptor.forClass(RegistrationParameters.class);
    verify(h.webAuthnManager)
        .verify(any(com.webauthn4j.data.RegistrationRequest.class), captor.capture());
    return captor.getValue().getPubKeyCredParams().stream()
        .map(p -> p.getAlg())
        .map(COSEAlgorithmIdentifier::getValue)
        .toList();
  }

  /** Wires a service over mocked collaborators with the supplied ceremony config. */
  private final class Harness {
    final WebAuthnManager webAuthnManager = mock(WebAuthnManager.class);
    final DefaultPasskeyAuthenticationService service;

    Harness(CeremonyConfig ceremonyConfig) {
      CredentialRepository credentialRepository = mock(CredentialRepository.class);
      UserLookup userLookup = mock(UserLookup.class);
      ChallengeStore challengeStore = mock(ChallengeStore.class);
      OriginValidator originValidator = mock(OriginValidator.class);
      AttestationTrustPolicy attestationTrustPolicy = mock(AttestationTrustPolicy.class);
      Metrics metrics = mock(Metrics.class);

      lenient().when(userLookup.getOrCreateHandle("alice")).thenReturn(USER_HANDLE);
      lenient().when(credentialRepository.findByUserHandle(USER_HANDLE)).thenReturn(List.of());
      lenient().when(originValidator.isAllowed("https://example.com")).thenReturn(true);
      lenient()
          .when(challengeStore.takeOnce(CHALLENGE_ID))
          .thenReturn(
              Optional.of(
                  new ChallengeRecord(
                      CHALLENGE,
                      ChallengeRecord.Purpose.REGISTRATION,
                      USER_HANDLE,
                      NOW.plusSeconds(300))));

      RelyingPartyConfig rp =
          new RelyingPartyConfig("example.com", "Example", Set.of("https://example.com"));
      SecureRandom random =
          new SecureRandom() {
            @Override
            public void nextBytes(byte[] bytes) {
              System.arraycopy(CHALLENGE, 0, bytes, 0, Math.min(bytes.length, CHALLENGE.length));
            }
          };
      this.service =
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
  }

  private FinishRegistrationRequest finishReg() {
    return new FinishRegistrationRequest(
        CHALLENGE_ID,
        "alice",
        "k",
        new RegistrationResponseJson(
            CRED_ID,
            CRED_ID,
            new AuthenticatorAttestationResponseJson(
                cd(), new byte[] {(byte) 0xa0}, null, null, null, null),
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
