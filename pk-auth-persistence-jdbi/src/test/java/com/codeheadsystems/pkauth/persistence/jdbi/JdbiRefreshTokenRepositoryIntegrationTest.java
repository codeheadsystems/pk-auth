// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.testkit.RefreshTokenScenarios;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@DisabledIfEnvironmentVariable(named = "PKAUTH_SKIP_TESTCONTAINERS", matches = "1")
class JdbiRefreshTokenRepositoryIntegrationTest {

  private JdbiRefreshTokenRepository repository;

  @BeforeEach
  void setUp() {
    Jdbi jdbi = PostgresFixture.ready();
    PostgresFixture.reset();
    repository = new JdbiRefreshTokenRepository(jdbi);
  }

  @Test
  void deleteExpiredBeforeRemovesRevokedExpiredRowsButKeepsFresh() {
    com.codeheadsystems.pkauth.api.UserHandle user =
        com.codeheadsystems.pkauth.api.UserHandle.of(new byte[] {1, 2, 3, 4});

    // Expired + revoked, both before the cutoff → eligible for cleanup.
    String staleId = "stale-" + java.util.UUID.randomUUID();
    repository.create(
        new com.codeheadsystems.pkauth.refresh.RefreshTokenRecord(
            staleId,
            new byte[32],
            user,
            "web",
            java.util.Optional.empty(),
            staleId,
            java.util.Optional.empty(),
            java.time.Instant.parse("2020-01-01T00:00:00Z"),
            java.time.Instant.parse("2020-02-01T00:00:00Z"),
            java.util.Optional.empty(),
            java.util.Optional.empty(),
            java.util.Optional.empty(),
            java.util.List.of("pkauth")));
    repository.revokeFamily(
        staleId,
        java.time.Instant.parse("2020-02-02T00:00:00Z"),
        com.codeheadsystems.pkauth.refresh.RevokeReason.ADMIN);

    // Still valid, well after the cutoff → must survive.
    String freshId = "fresh-" + java.util.UUID.randomUUID();
    repository.create(
        new com.codeheadsystems.pkauth.refresh.RefreshTokenRecord(
            freshId,
            new byte[32],
            user,
            "web",
            java.util.Optional.empty(),
            freshId,
            java.util.Optional.empty(),
            java.time.Instant.parse("2030-01-01T00:00:00Z"),
            java.time.Instant.parse("2030-02-01T00:00:00Z"),
            java.util.Optional.empty(),
            java.util.Optional.empty(),
            java.util.Optional.empty(),
            java.util.List.of("pkauth")));

    int removed = repository.deleteExpiredBefore(java.time.Instant.parse("2021-01-01T00:00:00Z"));
    assertThat(removed).isGreaterThanOrEqualTo(1);
    assertThat(repository.findByRefreshId(staleId)).isEmpty();
    assertThat(repository.findByRefreshId(freshId)).isPresent();
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

  /** The load-bearing concurrent rotation race test. Must pass against real Postgres. */
  @Test
  void concurrentRotationExactlyOneSucceedsFamilyRevoked() throws Exception {
    new RefreshTokenScenarios(repository).concurrentRotationExactlyOneSucceedsFamilyRevoked();
  }
}
