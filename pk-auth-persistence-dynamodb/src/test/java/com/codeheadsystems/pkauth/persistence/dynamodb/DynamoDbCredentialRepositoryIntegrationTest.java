// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.Transport;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Direct CRUD against {@link DynamoDbCredentialRepository}, covering the mutation paths ({@code
 * updateSignCount}, {@code updateLabel}, {@code delete}, {@code deleteByUserHandle}) the shared
 * ceremony scenarios don't exercise — including the clone-detection counter guard and the
 * ownership-mismatch no-ops.
 */
@Testcontainers
@DisabledIfEnvironmentVariable(named = "PKAUTH_SKIP_TESTCONTAINERS", matches = "1")
class DynamoDbCredentialRepositoryIntegrationTest {

  private static final Instant NOW = Instant.parse("2026-05-14T12:00:00Z");

  private DynamoDbCredentialRepository repository;

  @BeforeEach
  void setUp() {
    var client = DynamoDbLocalFixture.client();
    var enhanced = DynamoDbLocalFixture.enhanced();
    String suffix = UUID.randomUUID().toString().substring(0, 8);
    PkAuthDynamoTables tables =
        new PkAuthDynamoTables("PkAuthCore_" + suffix, "PkAuthUsers_" + suffix);
    new DynamoDbSchemaBootstrapper(client, tables).bootstrap();
    repository = new DynamoDbCredentialRepository(enhanced, tables);
  }

  private static CredentialRecord cred(
      CredentialId id, UserHandle user, long signCount, String label) {
    return new CredentialRecord(
        id,
        user,
        new byte[] {1, 2, 3, 4}, // repo round-trips raw COSE bytes; content isn't parsed here
        signCount,
        label,
        null,
        Set.of(Transport.USB),
        true,
        false,
        NOW,
        null);
  }

  private static CredentialId credId(byte... bytes) {
    return CredentialId.of(bytes);
  }

  @Test
  void saveFindAndListRoundTrip() {
    UserHandle user = UserHandle.random();
    CredentialId id = credId((byte) 1, (byte) 2, (byte) 3);
    repository.save(cred(id, user, 0L, "Laptop"));

    assertThat(repository.findByCredentialId(id))
        .hasValueSatisfying(
            r -> {
              assertThat(r.label()).isEqualTo("Laptop");
              assertThat(r.transports()).contains(Transport.USB);
            });
    assertThat(repository.findByUserHandle(user)).hasSize(1);
    assertThat(repository.findByCredentialId(credId((byte) 9))).isEmpty();
  }

  @Test
  void updateSignCountAdvancesCounter() {
    UserHandle user = UserHandle.random();
    CredentialId id = credId((byte) 4, (byte) 5);
    repository.save(cred(id, user, 0L, "k"));

    repository.updateSignCount(id, 42L, NOW.plusSeconds(60));
    assertThat(repository.findByCredentialId(id))
        .hasValueSatisfying(r -> assertThat(r.signCount()).isEqualTo(42L));
  }

  @Test
  void updateSignCountRejectsRegressionAndIsNoOpForUnknown() {
    UserHandle user = UserHandle.random();
    CredentialId id = credId((byte) 6, (byte) 7);
    repository.save(cred(id, user, 10L, "k"));

    // Counter regression: trying to lower the stored count must be refused (clone defence).
    repository.updateSignCount(id, 5L, NOW.plusSeconds(60));
    assertThat(repository.findByCredentialId(id))
        .hasValueSatisfying(r -> assertThat(r.signCount()).isEqualTo(10L));

    // Unknown credential is a silent no-op.
    repository.updateSignCount(credId((byte) 99), 1L, NOW);
  }

  @Test
  void updateLabelChangesLabelButHonoursOwnership() {
    UserHandle owner = UserHandle.random();
    UserHandle stranger = UserHandle.random();
    CredentialId id = credId((byte) 8, (byte) 9);
    repository.save(cred(id, owner, 0L, "Old"));

    // Wrong owner → silent no-op.
    repository.updateLabel(stranger, id, "Hacked");
    assertThat(repository.findByCredentialId(id))
        .hasValueSatisfying(r -> assertThat(r.label()).isEqualTo("Old"));

    // Correct owner → renamed.
    repository.updateLabel(owner, id, "New");
    assertThat(repository.findByCredentialId(id))
        .hasValueSatisfying(r -> assertThat(r.label()).isEqualTo("New"));

    // Unknown credential → no-op (no throw).
    repository.updateLabel(owner, credId((byte) 70), "X");
  }

  @Test
  void deleteHonoursOwnershipAndRemovesRow() {
    UserHandle owner = UserHandle.random();
    UserHandle stranger = UserHandle.random();
    CredentialId id = credId((byte) 10, (byte) 11);
    repository.save(cred(id, owner, 0L, "k"));

    // Wrong owner → not deleted.
    repository.delete(stranger, id);
    assertThat(repository.findByCredentialId(id)).isPresent();

    // Correct owner → deleted.
    repository.delete(owner, id);
    assertThat(repository.findByCredentialId(id)).isEmpty();

    // Unknown credential → no-op.
    repository.delete(owner, credId((byte) 71));
  }

  @Test
  void deleteByUserHandleRemovesAllOfTheUsersCredentials() {
    UserHandle user = UserHandle.random();
    UserHandle other = UserHandle.random();
    repository.save(cred(credId((byte) 20), user, 0L, "a"));
    repository.save(cred(credId((byte) 21), user, 0L, "b"));
    repository.save(cred(credId((byte) 22), other, 0L, "c"));

    int removed = repository.deleteByUserHandle(user);
    assertThat(removed).isEqualTo(2);
    assertThat(repository.findByUserHandle(user)).isEmpty();
    assertThat(repository.findByUserHandle(other)).hasSize(1);
  }
}
