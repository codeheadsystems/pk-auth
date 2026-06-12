// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationServices;
import com.codeheadsystems.pkauth.metrics.Metrics;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.testkit.CeremonyScenarios;
import com.codeheadsystems.pkauth.testkit.FakeAuthenticator;
import com.codeheadsystems.pkauth.testkit.PkAuthFixtures;
import com.webauthn4j.converter.util.ObjectConverter;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Drives the shared {@link CeremonyScenarios} against the JDBI/Postgres backend. Requires Docker
 * (Testcontainers); skipped when {@code PKAUTH_SKIP_TESTCONTAINERS=1}.
 */
@Testcontainers
@DisabledIfEnvironmentVariable(named = "PKAUTH_SKIP_TESTCONTAINERS", matches = "1")
class JdbiCeremonyIntegrationTest {

  private Jdbi jdbi;
  private JdbiCredentialRepository credentialRepository;
  private JdbiChallengeStore challengeStore;
  private JdbiUserLookup userLookup;
  private PasskeyAuthenticationService service;
  private FakeAuthenticator authenticator;

  @BeforeEach
  void setUp() {
    jdbi = PostgresFixture.ready();
    PostgresFixture.reset();
    credentialRepository = new JdbiCredentialRepository(jdbi);
    challengeStore = new JdbiChallengeStore(jdbi);
    userLookup = new JdbiUserLookup(jdbi);

    ObjectConverter objectConverter = new ObjectConverter();
    authenticator =
        FakeAuthenticator.builder()
            .origin(PkAuthFixtures.DEFAULT_ORIGIN)
            .rpId(PkAuthFixtures.DEFAULT_RP_ID)
            .objectConverter(objectConverter)
            .build();
    service =
        PasskeyAuthenticationServices.builder()
            .credentialRepository(credentialRepository)
            .userLookup(userLookup)
            .challengeStore(challengeStore)
            .relyingPartyConfig(PkAuthFixtures.defaultRelyingParty())
            .ceremonyConfig(PkAuthFixtures.defaultCeremonyConfig())
            .clockProvider(ClockProvider.system())
            .objectConverter(objectConverter)
            .metrics(Metrics.noop())
            .build();
  }

  @Test
  void registrationThenAssertionAgainstPostgres() {
    new CeremonyScenarios(service, authenticator, credentialRepository, userLookup)
        .registrationThenAssertionBumpsSignCount();
    UserHandle handle = userLookup.findHandleByUsername(CeremonyScenarios.USERNAME).orElseThrow();
    assertThat(credentialRepository.findByUserHandle(handle)).hasSize(1);
  }

  @Test
  void usernamelessFlowAgainstPostgres() {
    new CeremonyScenarios(service, authenticator, credentialRepository, userLookup)
        .usernamelessFlowSucceedsWithSingleCredential();
  }

  @Test
  void tamperedAssertionRejectedAgainstPostgres() {
    new CeremonyScenarios(service, authenticator, credentialRepository, userLookup)
        .tamperedAssertionSignatureIsRejected();
  }

  @Test
  void tamperedRegistrationRejectedAgainstPostgres() {
    new CeremonyScenarios(service, authenticator, credentialRepository, userLookup)
        .tamperedRegistrationPayloadIsRejected();
  }

  @Test
  void replayedAssertionRejectedAgainstPostgres() {
    new CeremonyScenarios(service, authenticator, credentialRepository, userLookup)
        .replayedAssertionChallengeIsRejected();
  }

  @Test
  void challengeStoreTakeOnceConsumesAtomically() {
    challengeStore.put(
        new com.codeheadsystems.pkauth.api.ChallengeId("ch-1"),
        new com.codeheadsystems.pkauth.spi.ChallengeRecord(
            new byte[] {1, 2, 3},
            com.codeheadsystems.pkauth.spi.ChallengeRecord.Purpose.REGISTRATION,
            null,
            java.time.Instant.now().plusSeconds(60)),
        java.time.Duration.ofMinutes(1));

    assertThat(challengeStore.takeOnce(new com.codeheadsystems.pkauth.api.ChallengeId("ch-1")))
        .isPresent();
    assertThat(challengeStore.takeOnce(new com.codeheadsystems.pkauth.api.ChallengeId("ch-1")))
        .isEmpty();
  }

  @Test
  void challengeStoreSingleUseUnderConcurrency() throws Exception {
    new com.codeheadsystems.pkauth.testkit.ChallengeStoreScenarios(challengeStore)
        .concurrentTakeOnceYieldsExactlyOneWinner();
  }
}
