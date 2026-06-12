// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.codeheadsystems.pkauth.api.AssertionResult;
import com.codeheadsystems.pkauth.api.CeremonyWireMapper.CeremonyResponse;
import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.RegistrationResult;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResponse;
import com.codeheadsystems.pkauth.api.StartAuthenticationResult;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResponse;
import com.codeheadsystems.pkauth.api.StartRegistrationResult;
import com.codeheadsystems.pkauth.api.Transport;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.credential.AuthenticatorData;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CeremonyOrchestratorTest {

  private static final UserHandle USER = UserHandle.of(new byte[] {1, 2, 3, 4});
  private static final CredentialId CRED = CredentialId.of(new byte[] {5, 6, 7, 8});

  private PasskeyAuthenticationService service;
  private PkAuthJwtIssuer issuer;
  private CredentialRepository credentialRepository;
  private CeremonyOrchestrator orchestrator;

  @BeforeEach
  void setUp() {
    service = mock(PasskeyAuthenticationService.class);
    issuer = mock(PkAuthJwtIssuer.class);
    credentialRepository = mock(CredentialRepository.class);
    orchestrator = new CeremonyOrchestrator(service, issuer, credentialRepository);
  }

  @Test
  void constructorRejectsNulls() {
    assertThatThrownBy(() -> new CeremonyOrchestrator(null, issuer, credentialRepository))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new CeremonyOrchestrator(service, null, credentialRepository))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new CeremonyOrchestrator(service, issuer, null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void startRegistrationDelegates() {
    StartRegistrationRequest req = mock(StartRegistrationRequest.class);
    StartRegistrationResult resp =
        new StartRegistrationResult.Started(mock(StartRegistrationResponse.class));
    when(service.startRegistration(req, "1.2.3.4")).thenReturn(resp);
    assertThat(orchestrator.startRegistration(req, "1.2.3.4")).isSameAs(resp);
  }

  @Test
  void startAuthenticationDelegates() {
    StartAuthenticationRequest req = mock(StartAuthenticationRequest.class);
    StartAuthenticationResult resp =
        new StartAuthenticationResult.Started(mock(StartAuthenticationResponse.class));
    when(service.startAuthentication(req, null)).thenReturn(resp);
    assertThat(orchestrator.startAuthentication(req, null)).isSameAs(resp);
  }

  @Test
  void finishRegistrationSuccessReturns200() {
    CredentialRecord record = sampleCredential("token-key");
    when(service.finishRegistration(any(), any()))
        .thenReturn(new RegistrationResult.Success(record, mock(AuthenticatorData.class)));
    CeremonyResponse wire =
        orchestrator.finishRegistration(mock(FinishRegistrationRequest.class), null);
    assertThat(wire.status()).isEqualTo(200);
    assertThat(wire.body()).containsEntry("outcome", "success");
  }

  @Test
  void finishRegistrationErrorReturnsMappedStatus() {
    when(service.finishRegistration(any(), any()))
        .thenReturn(new RegistrationResult.InvalidPayload("nope"));
    CeremonyResponse wire =
        orchestrator.finishRegistration(mock(FinishRegistrationRequest.class), null);
    assertThat(wire.status()).isEqualTo(400);
    assertThat(wire.body()).containsEntry("outcome", "invalid_payload");
  }

  @Test
  void finishAuthenticationSuccessMintsJwtAndEmbedsLabel() {
    when(service.finishAuthentication(any(), any()))
        .thenReturn(new AssertionResult.Success(USER, CRED, 42L, AssertionResult.CounterStatus.OK));
    when(issuer.issue(any())).thenReturn("signed-jwt-value");
    when(credentialRepository.findByCredentialId(CRED))
        .thenReturn(Optional.of(sampleCredential("the-key-label")));

    CeremonyResponse wire =
        orchestrator.finishAuthentication(mock(FinishAuthenticationRequest.class), "10.0.0.1");

    assertThat(wire.status()).isEqualTo(200);
    assertThat(wire.body()).containsEntry("outcome", "success");
    assertThat(wire.body()).containsEntry("token", "signed-jwt-value");
    assertThat(wire.body()).containsEntry("label", "the-key-label");
    assertThat(wire.body()).containsEntry("signCount", 42L);
  }

  @Test
  void finishAuthenticationSuccessHandlesMissingCredentialLabel() {
    when(service.finishAuthentication(any(), any()))
        .thenReturn(new AssertionResult.Success(USER, CRED, 1L, AssertionResult.CounterStatus.OK));
    when(issuer.issue(any())).thenReturn("jwt");
    when(credentialRepository.findByCredentialId(CRED)).thenReturn(Optional.empty());

    CeremonyResponse wire =
        orchestrator.finishAuthentication(mock(FinishAuthenticationRequest.class), null);

    assertThat(wire.status()).isEqualTo(200);
    assertThat(wire.body()).doesNotContainKey("label");
  }

  @Test
  void finishAuthenticationErrorReturnsMappedStatus() {
    when(service.finishAuthentication(any(), any()))
        .thenReturn(new AssertionResult.UnknownCredential(CRED));
    CeremonyResponse wire =
        orchestrator.finishAuthentication(mock(FinishAuthenticationRequest.class), null);
    assertThat(wire.status()).isEqualTo(404);
    assertThat(wire.body()).containsEntry("outcome", "unknown_credential");
  }

  @Test
  void rateLimitedReturnsCanonicalShape() {
    CeremonyResponse wire = orchestrator.rateLimited();
    assertThat(wire.status()).isEqualTo(429);
    assertThat(wire.body()).containsEntry("outcome", "rate_limited");
  }

  private static CredentialRecord sampleCredential(String label) {
    return new CredentialRecord(
        CRED,
        USER,
        new byte[] {1},
        0L,
        label,
        null,
        EnumSet.noneOf(Transport.class),
        false,
        false,
        Instant.parse("2026-01-01T00:00:00Z"),
        null);
  }
}
