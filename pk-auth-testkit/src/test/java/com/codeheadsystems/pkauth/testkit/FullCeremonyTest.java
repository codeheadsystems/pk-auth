// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.credential.CredentialRecord;
import org.junit.jupiter.api.Test;

/**
 * Phase 3 acceptance test: drive {@link CeremonyScenarios} against the in-memory implementations.
 * The same scenarios are also driven against JDBI and DynamoDB backends in Phase 5.
 */
class FullCeremonyTest {

  @Test
  void registrationThenAssertionSucceedsAndBumpsSignCount() {
    InMemoryEverything env = InMemoryEverything.defaults();
    CeremonyScenarios scenarios =
        new CeremonyScenarios(env.service, env.authenticator, env.credentials, env.users);

    scenarios.registrationThenAssertionBumpsSignCount();

    assertThat(env.challenges.size()).isZero(); // single-use challenge store
  }

  @Test
  void usernamelessFlowSucceedsWhenSingleCredentialRegistered() {
    InMemoryEverything env = InMemoryEverything.defaults();
    CeremonyScenarios scenarios =
        new CeremonyScenarios(env.service, env.authenticator, env.credentials, env.users);

    scenarios.usernamelessFlowSucceedsWithSingleCredential();
  }

  @Test
  void tamperedAssertionSignatureIsRejected() {
    InMemoryEverything env = InMemoryEverything.defaults();
    CeremonyScenarios scenarios =
        new CeremonyScenarios(env.service, env.authenticator, env.credentials, env.users);

    scenarios.tamperedAssertionSignatureIsRejected();

    assertThat(env.challenges.size()).isZero(); // challenge still consumed on rejection
  }

  @Test
  void tamperedRegistrationPayloadIsRejected() {
    InMemoryEverything env = InMemoryEverything.defaults();
    CeremonyScenarios scenarios =
        new CeremonyScenarios(env.service, env.authenticator, env.credentials, env.users);

    scenarios.tamperedRegistrationPayloadIsRejected();
  }

  @Test
  void replayedAssertionChallengeIsRejected() {
    InMemoryEverything env = InMemoryEverything.defaults();
    CeremonyScenarios scenarios =
        new CeremonyScenarios(env.service, env.authenticator, env.credentials, env.users);

    scenarios.replayedAssertionChallengeIsRejected();
  }

  @Test
  void duplicateRegistrationIsRejectedOnSecondAttempt() {
    InMemoryEverything env = InMemoryEverything.defaults();
    CeremonyScenarios scenarios =
        new CeremonyScenarios(env.service, env.authenticator, env.credentials, env.users);
    scenarios.register();

    CredentialRecord existing =
        env.credentials
            .findByUserHandle(
                env.users.findHandleByUsername(CeremonyScenarios.USERNAME).orElseThrow())
            .get(0);
    assertThatThrownBy(() -> env.credentials.save(existing))
        .isInstanceOf(com.codeheadsystems.pkauth.spi.DuplicateCredentialException.class)
        .hasMessageContaining("Duplicate");
  }
}
