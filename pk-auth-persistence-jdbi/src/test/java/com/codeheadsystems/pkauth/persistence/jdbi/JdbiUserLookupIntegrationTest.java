// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.UserLookup.UserView;
import java.util.Optional;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Covers {@link JdbiUserLookup}'s registration / lookup surface — {@code getOrCreateHandle} (create
 * + idempotent re-fetch), {@code findHandleByUsername}, {@code register}, and {@code
 * findViewByHandle} / {@code readView} — which the ceremony scenarios only touch via {@code
 * getOrCreateHandle}.
 */
@Testcontainers
@DisabledIfEnvironmentVariable(named = "PKAUTH_SKIP_TESTCONTAINERS", matches = "1")
class JdbiUserLookupIntegrationTest {

  private JdbiUserLookup users;

  @BeforeEach
  void setUp() {
    Jdbi jdbi = PostgresFixture.ready();
    PostgresFixture.reset();
    users = new JdbiUserLookup(jdbi);
  }

  @Test
  void getOrCreateHandleIsIdempotentForSameUsername() {
    UserHandle first = users.getOrCreateHandle("alice");
    UserHandle second = users.getOrCreateHandle("alice");
    assertThat(second).isEqualTo(first);
  }

  @Test
  void findHandleByUsernameReflectsCreationAndMissesUnknown() {
    UserHandle handle = users.getOrCreateHandle("bob");
    assertThat(users.findHandleByUsername("bob")).hasValue(handle);
    assertThat(users.findHandleByUsername("nobody")).isEmpty();
  }

  @Test
  void findViewByHandleReturnsUsernameForKnownAndEmptyForUnknown() {
    UserHandle handle = users.getOrCreateHandle("carol");
    Optional<UserView> view = users.findViewByHandle(handle);
    assertThat(view)
        .hasValueSatisfying(
            v -> {
              assertThat(v.handle()).isEqualTo(handle);
              assertThat(v.username()).isEqualTo("carol");
            });
    assertThat(users.findViewByHandle(UserHandle.random())).isEmpty();
  }

  @Test
  void getOrCreateHandleIsCaseInsensitiveAndPreservesOriginalCasing() {
    // Matches DynamoDbUserLookup, which keys identity on lower(username). Before V12 the JDBI
    // backend matched exactly, so "Alice" and "alice" were two accounts on Postgres and one on
    // DynamoDB — the same host code produced different identity models per backend.
    UserHandle first = users.getOrCreateHandle("Alice");
    assertThat(users.getOrCreateHandle("alice")).isEqualTo(first);
    assertThat(users.getOrCreateHandle("ALICE")).isEqualTo(first);

    // Uniqueness folds, but the stored form keeps the casing it was created with.
    assertThat(users.findViewByHandle(first))
        .hasValueSatisfying(v -> assertThat(v.username()).isEqualTo("Alice"));
  }

  @Test
  void findHandleByUsernameIsCaseInsensitive() {
    UserHandle handle = users.getOrCreateHandle("Bob");
    assertThat(users.findHandleByUsername("bob")).hasValue(handle);
    assertThat(users.findHandleByUsername("BOB")).hasValue(handle);
    assertThat(users.findHandleByUsername("bOb")).hasValue(handle);
  }

  @Test
  void registerRejectsAUsernameDifferingOnlyByCase() {
    users.register("dana", "Dana");
    // The V12 unique index on lower(username) is what enforces this — without it a second row
    // would be created and lookups would resolve non-deterministically between the two.
    org.assertj.core.api.Assertions.assertThatThrownBy(() -> users.register("DANA", "Impostor"))
        .isInstanceOf(com.codeheadsystems.pkauth.spi.PkAuthPersistenceException.class);
  }

  @Test
  void registerPersistsUsernameAndDisplayName() {
    UserHandle handle = users.register("dave", "Dave Display");
    assertThat(users.findHandleByUsername("dave")).hasValue(handle);
    assertThat(users.findViewByHandle(handle))
        .hasValueSatisfying(
            v -> {
              assertThat(v.username()).isEqualTo("dave");
              assertThat(v.displayName()).isEqualTo("Dave Display");
            });
  }
}
