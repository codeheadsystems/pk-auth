// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationServices;
import com.codeheadsystems.pkauth.metrics.Metrics;
import com.codeheadsystems.pkauth.spi.ChallengeRecord;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.testkit.CeremonyScenarios;
import com.codeheadsystems.pkauth.testkit.FakeAuthenticator;
import com.codeheadsystems.pkauth.testkit.PkAuthFixtures;
import com.webauthn4j.converter.util.ObjectConverter;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.testcontainers.junit.jupiter.Testcontainers;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

/**
 * Drives the shared {@link CeremonyScenarios} against DynamoDB Local. Each test class run creates
 * its own pair of tables (random suffix) so concurrent test classes do not collide.
 */
@Testcontainers
@DisabledIfEnvironmentVariable(named = "PKAUTH_SKIP_TESTCONTAINERS", matches = "1")
class DynamoDbCeremonyIntegrationTest {

  private DynamoDbClient client;
  private DynamoDbEnhancedClient enhanced;
  private PkAuthDynamoTables tables;
  private DynamoDbCredentialRepository credentialRepository;
  private DynamoDbChallengeStore challengeStore;
  private DynamoDbUserLookup userLookup;
  private PasskeyAuthenticationService service;
  private FakeAuthenticator authenticator;

  @BeforeEach
  void setUp() {
    client = DynamoDbLocalFixture.client();
    enhanced = DynamoDbLocalFixture.enhanced();
    String suffix = UUID.randomUUID().toString().substring(0, 8);
    tables = new PkAuthDynamoTables("PkAuthCore_" + suffix, "PkAuthUsers_" + suffix);
    new DynamoDbSchemaBootstrapper(client, tables).bootstrap();

    credentialRepository = new DynamoDbCredentialRepository(enhanced, tables);
    challengeStore = new DynamoDbChallengeStore(client, tables);
    userLookup = new DynamoDbUserLookup(enhanced, tables);

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
  void registrationThenAssertionAgainstDynamoDb() {
    new CeremonyScenarios(service, authenticator, credentialRepository, userLookup)
        .registrationThenAssertionBumpsSignCount();
    UserHandle handle = userLookup.findHandleByUsername(CeremonyScenarios.USERNAME).orElseThrow();
    assertThat(credentialRepository.findByUserHandle(handle)).hasSize(1);
  }

  @Test
  void usernamelessFlowAgainstDynamoDb() {
    new CeremonyScenarios(service, authenticator, credentialRepository, userLookup)
        .usernamelessFlowSucceedsWithSingleCredential();
  }

  @Test
  void tamperedAssertionRejectedAgainstDynamoDb() {
    new CeremonyScenarios(service, authenticator, credentialRepository, userLookup)
        .tamperedAssertionSignatureIsRejected();
  }

  @Test
  void tamperedRegistrationRejectedAgainstDynamoDb() {
    new CeremonyScenarios(service, authenticator, credentialRepository, userLookup)
        .tamperedRegistrationPayloadIsRejected();
  }

  @Test
  void replayedAssertionRejectedAgainstDynamoDb() {
    new CeremonyScenarios(service, authenticator, credentialRepository, userLookup)
        .replayedAssertionChallengeIsRejected();
  }

  @Test
  void challengeTakeOnceIsSingleUse() {
    ChallengeId id = new ChallengeId("ch-" + UUID.randomUUID());
    challengeStore.put(
        id,
        new ChallengeRecord(
            new byte[] {1, 2, 3},
            ChallengeRecord.Purpose.REGISTRATION,
            null,
            Instant.now().plusSeconds(60)),
        Duration.ofMinutes(1));

    assertThat(challengeStore.takeOnce(id)).isPresent();
    assertThat(challengeStore.takeOnce(id)).isEmpty();
  }

  @Test
  void challengeStoreSingleUseUnderConcurrency() throws Exception {
    new com.codeheadsystems.pkauth.testkit.ChallengeStoreScenarios(challengeStore)
        .concurrentTakeOnceYieldsExactlyOneWinner();
  }
}
