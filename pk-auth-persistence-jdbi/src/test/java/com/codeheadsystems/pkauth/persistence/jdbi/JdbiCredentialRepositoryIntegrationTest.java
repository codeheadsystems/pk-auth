// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.Transport;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import java.time.Instant;
import java.util.Set;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Direct CRUD against {@link JdbiCredentialRepository}, covering the mutation paths ({@code
 * updateSignCount}, {@code updateLabel}, {@code delete}, {@code deleteByUserHandle}) and the
 * transport (de)serialization the shared ceremony scenarios don't exercise — including the
 * clone-detection counter guard and the ownership-scoped no-ops.
 */
@Testcontainers
@DisabledIfEnvironmentVariable(named = "PKAUTH_SKIP_TESTCONTAINERS", matches = "1")
class JdbiCredentialRepositoryIntegrationTest {

  private static final Instant NOW = Instant.parse("2026-05-14T12:00:00Z");

  private JdbiCredentialRepository repository;

  @BeforeEach
  void setUp() {
    Jdbi jdbi = PostgresFixture.ready();
    PostgresFixture.reset();
    repository = new JdbiCredentialRepository(jdbi);
  }

  private static CredentialRecord cred(
      CredentialId id, UserHandle user, long signCount, String label, Set<Transport> transports) {
    return new CredentialRecord(
        id,
        user,
        new byte[] {1, 2, 3, 4},
        signCount,
        label,
        null,
        transports,
        true,
        false,
        NOW,
        null);
  }

  private static CredentialId credId(byte... bytes) {
    return CredentialId.of(bytes);
  }

  @Test
  void saveFindAndListRoundTripPreservesTransports() {
    UserHandle user = UserHandle.random();
    CredentialId multi = credId((byte) 1, (byte) 2);
    CredentialId none = credId((byte) 3, (byte) 4);
    repository.save(cred(multi, user, 0L, "Laptop", Set.of(Transport.USB, Transport.NFC)));
    repository.save(cred(none, user, 0L, "Phone", Set.of()));

    assertThat(repository.findByCredentialId(multi))
        .hasValueSatisfying(
            r ->
                assertThat(r.transports()).containsExactlyInAnyOrder(Transport.USB, Transport.NFC));
    assertThat(repository.findByCredentialId(none))
        .hasValueSatisfying(r -> assertThat(r.transports()).isEmpty());
    assertThat(repository.findByUserHandle(user)).hasSize(2);
    assertThat(repository.findByCredentialId(credId((byte) 9))).isEmpty();
  }

  @Test
  void updateSignCountAdvancesButRejectsRegression() {
    UserHandle user = UserHandle.random();
    CredentialId id = credId((byte) 5, (byte) 6);
    repository.save(cred(id, user, 10L, "k", Set.of()));

    repository.updateSignCount(id, 42L, NOW.plusSeconds(60));
    assertThat(repository.findByCredentialId(id))
        .hasValueSatisfying(r -> assertThat(r.signCount()).isEqualTo(42L));

    // Regression (lower than stored) must be refused — clone-detection guard.
    repository.updateSignCount(id, 7L, NOW.plusSeconds(120));
    assertThat(repository.findByCredentialId(id))
        .hasValueSatisfying(r -> assertThat(r.signCount()).isEqualTo(42L));
  }

  @Test
  void updateLabelHonoursOwnership() {
    UserHandle owner = UserHandle.random();
    UserHandle stranger = UserHandle.random();
    CredentialId id = credId((byte) 7, (byte) 8);
    repository.save(cred(id, owner, 0L, "Old", Set.of()));

    repository.updateLabel(stranger, id, "Hacked");
    assertThat(repository.findByCredentialId(id))
        .hasValueSatisfying(r -> assertThat(r.label()).isEqualTo("Old"));

    repository.updateLabel(owner, id, "New");
    assertThat(repository.findByCredentialId(id))
        .hasValueSatisfying(r -> assertThat(r.label()).isEqualTo("New"));
  }

  @Test
  void deleteHonoursOwnershipAndRemovesRow() {
    UserHandle owner = UserHandle.random();
    UserHandle stranger = UserHandle.random();
    CredentialId id = credId((byte) 9, (byte) 10);
    repository.save(cred(id, owner, 0L, "k", Set.of()));

    repository.delete(stranger, id);
    assertThat(repository.findByCredentialId(id)).isPresent();

    repository.delete(owner, id);
    assertThat(repository.findByCredentialId(id)).isEmpty();
  }

  @Test
  void deleteByUserHandleRemovesAllOfTheUsersCredentials() {
    UserHandle user = UserHandle.random();
    UserHandle other = UserHandle.random();
    repository.save(cred(credId((byte) 20), user, 0L, "a", Set.of()));
    repository.save(cred(credId((byte) 21), user, 0L, "b", Set.of()));
    repository.save(cred(credId((byte) 22), other, 0L, "c", Set.of()));

    int removed = repository.deleteByUserHandle(user);
    assertThat(removed).isEqualTo(2);
    assertThat(repository.findByUserHandle(user)).isEmpty();
    assertThat(repository.findByUserHandle(other)).hasSize(1);
  }
}
