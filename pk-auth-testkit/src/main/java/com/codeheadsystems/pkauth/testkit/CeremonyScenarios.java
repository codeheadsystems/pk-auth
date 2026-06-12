// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.AssertionResult;
import com.codeheadsystems.pkauth.api.AuthenticationResponseJson;
import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson;
import com.codeheadsystems.pkauth.api.RegistrationResult;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResponse;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResponse;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;
import java.util.Optional;

/**
 * Shared ceremony scenarios used as the acceptance bar for Phase 3 (in-memory) and Phase 5 (JDBI,
 * DynamoDB). Persistence modules drive a real backend through the same flow that {@code
 * DefaultPasskeyAuthenticationService} runs in production.
 *
 * <p>Construct with a {@link PasskeyAuthenticationService}, a {@link FakeAuthenticator}, and direct
 * access to the repositories the service was built from. Then invoke the named scenarios.
 */
public final class CeremonyScenarios {

  /** Common username used by every scenario so persistence-layer state is comparable. */
  public static final String USERNAME = "alice";

  /** Common display name. */
  public static final String DISPLAY_NAME = "Alice";

  /** Common credential label. */
  public static final String LABEL = "Test key";

  private final PasskeyAuthenticationService service;
  private final FakeAuthenticator authenticator;
  private final CredentialRepository credentials;
  private final UserLookup users;

  public CeremonyScenarios(
      PasskeyAuthenticationService service,
      FakeAuthenticator authenticator,
      CredentialRepository credentials,
      UserLookup users) {
    this.service = service;
    this.authenticator = authenticator;
    this.credentials = credentials;
    this.users = users;
  }

  /**
   * Full happy-path scenario: register a user + credential, then assert twice; the sign counter
   * increments on both the FakeAuthenticator's local state and in the repository.
   */
  public void registrationThenAssertionBumpsSignCount() {
    UserHandle handle = register();

    Optional<CredentialRecord> stored = singleCredentialFor(handle);
    assertThat(stored).isPresent();
    CredentialRecord credential = stored.orElseThrow();
    assertThat(credential.signCount()).isZero();
    CredentialId credentialId = credential.credentialId();

    AssertionResult first = assertOnce(handle);
    assertThat(first)
        .isInstanceOfSatisfying(
            AssertionResult.Success.class, s -> assertThat(s.signCount()).isEqualTo(1L));

    AssertionResult second = assertOnce(handle);
    assertThat(second)
        .isInstanceOfSatisfying(
            AssertionResult.Success.class, s -> assertThat(s.signCount()).isEqualTo(2L));

    assertThat(credentials.findByCredentialId(credentialId).orElseThrow().signCount())
        .isEqualTo(2L);
  }

  /**
   * Usernameless flow: startAuthentication with a null username returns options with an empty
   * {@code allowCredentials} list (never {@code null} — account-enumeration guard); the
   * FakeAuthenticator picks the sole registered credential and assertion succeeds.
   */
  public void usernamelessFlowSucceedsWithSingleCredential() {
    UserHandle handle = register();

    StartAuthenticationResponse start =
        service.startAuthentication(new StartAuthenticationRequest(null, null));
    assertThat(start.publicKey().allowCredentials()).isNotNull().isEmpty();

    AuthenticationResponseJson resp = authenticator.createAssertionResponse(start, handle);
    AssertionResult result =
        service.finishAuthentication(new FinishAuthenticationRequest(start.challengeId(), resp));
    assertThat(result).isInstanceOf(AssertionResult.Success.class);
  }

  /** Registers a single credential and returns the issued user handle. */
  public UserHandle register() {
    StartRegistrationResponse start =
        service.startRegistration(new StartRegistrationRequest(USERNAME, DISPLAY_NAME, null, null));
    RegistrationResponseJson resp = authenticator.createRegistrationResponse(start);
    RegistrationResult result =
        service.finishRegistration(
            new FinishRegistrationRequest(start.challengeId(), USERNAME, LABEL, resp));
    assertThat(result).isInstanceOf(RegistrationResult.Success.class);
    return ((RegistrationResult.Success) result).credential().userHandle();
  }

  /** Runs a single assertion for the registered username. */
  public AssertionResult assertOnce(UserHandle handle) {
    StartAuthenticationResponse start =
        service.startAuthentication(new StartAuthenticationRequest(USERNAME, null));
    AuthenticationResponseJson resp = authenticator.createAssertionResponse(start, handle);
    return service.finishAuthentication(new FinishAuthenticationRequest(start.challengeId(), resp));
  }

  private Optional<CredentialRecord> singleCredentialFor(UserHandle handle) {
    return credentials.findByUserHandle(handle).stream().findFirst();
  }

  /** Returns the underlying user lookup for assertions in caller-supplied test fixtures. */
  public UserLookup users() {
    return users;
  }
}
