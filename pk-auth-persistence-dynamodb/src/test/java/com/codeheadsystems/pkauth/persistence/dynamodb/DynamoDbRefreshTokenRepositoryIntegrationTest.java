// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.refresh.RefreshTokenRecord;
import com.codeheadsystems.pkauth.testkit.RefreshTokenScenarios;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.testcontainers.junit.jupiter.Testcontainers;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;

@Testcontainers
@DisabledIfEnvironmentVariable(named = "PKAUTH_SKIP_TESTCONTAINERS", matches = "1")
class DynamoDbRefreshTokenRepositoryIntegrationTest {

  private DynamoDbRefreshTokenRepository repository;
  private DynamoDbClient client;
  private DynamoDbEnhancedClient enhanced;
  private String coreTable;

  @BeforeEach
  void setUp() {
    client = DynamoDbLocalFixture.client();
    enhanced = DynamoDbLocalFixture.enhanced();
    String suffix = UUID.randomUUID().toString().substring(0, 8);
    coreTable = "PkAuthCore_" + suffix;
    PkAuthDynamoTables tables = new PkAuthDynamoTables(coreTable, "PkAuthUsers_" + suffix);
    new DynamoDbSchemaBootstrapper(client, tables).bootstrap();
    repository = new DynamoDbRefreshTokenRepository(enhanced, tables);
  }

  /**
   * The native-TTL {@code ttl} attribute must carry {@code expiresAt + cleanupRetention} so the
   * background sweep keeps used/revoked rows through the forensic window (parity with JDBI), while
   * {@code expiresAtEpoch} carries the unextended hard expiry used by the freshness check.
   */
  @Test
  void nativeTtlExtendsExpiryByCleanupRetention() {
    String suffix = UUID.randomUUID().toString().substring(0, 8);
    PkAuthDynamoTables tables = new PkAuthDynamoTables(coreTable, "PkAuthUsers_" + suffix);
    Duration retention = Duration.ofDays(7);
    DynamoDbRefreshTokenRepository retentionRepo =
        new DynamoDbRefreshTokenRepository(enhanced, tables, retention);

    Instant expiresAt = Instant.parse("2030-01-01T00:00:00Z");
    String refreshId = "rid-" + suffix;
    RefreshTokenRecord record =
        new RefreshTokenRecord(
            refreshId,
            new byte[32],
            UserHandle.of(new byte[] {1, 2, 3, 4}),
            "web",
            Optional.empty(),
            refreshId,
            Optional.empty(),
            Instant.parse("2029-12-18T00:00:00Z"),
            expiresAt,
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            List.of("pkauth", "webauthn"));
    retentionRepo.create(record);

    Map<String, AttributeValue> item =
        client
            .getItem(
                GetItemRequest.builder()
                    .tableName(coreTable)
                    .key(
                        Map.of(
                            "pk", AttributeValue.fromS("RT#" + refreshId),
                            "sk", AttributeValue.fromS("RT#" + refreshId)))
                    .build())
            .item();

    assertThat(item).isNotEmpty();
    assertThat(Long.parseLong(item.get("expiresAtEpoch").n()))
        .isEqualTo(expiresAt.getEpochSecond());
    assertThat(Long.parseLong(item.get("ttl").n()))
        .isEqualTo(expiresAt.plus(retention).getEpochSecond());
  }

  @Test
  void issueRotateRevokeHappyPath() {
    new RefreshTokenScenarios(repository).issueRotateRevokeHappyPath();
  }

  @Test
  void rotationUpdatesFamilyChainAndChildLinksToParent() {
    new RefreshTokenScenarios(repository).rotationUpdatesFamilyChainAndChildLinksToParent();
  }

  @Test
  void replayOfUsedTokenScorchesEntireFamily() {
    new RefreshTokenScenarios(repository).replayOfUsedTokenScorchesEntireFamily();
  }

  @Test
  void expiredTokenRotationReturnsExpired() {
    new RefreshTokenScenarios(repository).expiredTokenRotationReturnsExpired();
  }

  @Test
  void unknownRefreshIdReturnsUnknown() {
    new RefreshTokenScenarios(repository).unknownRefreshIdReturnsUnknown();
  }

  @Test
  void wrongSecretReturnsUnknownAndDoesNotBurnLegitToken() {
    new RefreshTokenScenarios(repository).wrongSecretReturnsUnknownAndDoesNotBurnLegitToken();
  }

  @Test
  void revokeFamilyIsIdempotent() {
    new RefreshTokenScenarios(repository).revokeFamilyIsIdempotent();
  }

  @Test
  void revokeAllForUserRevokesEveryActiveFamily() {
    new RefreshTokenScenarios(repository).revokeAllForUserRevokesEveryActiveFamily();
  }

  /** The load-bearing concurrent rotation race test. Must pass against real DynamoDB Local. */
  @Test
  void concurrentRotationExactlyOneSucceedsFamilyRevoked() throws Exception {
    new RefreshTokenScenarios(repository).concurrentRotationExactlyOneSucceedsFamilyRevoked();
  }
}
