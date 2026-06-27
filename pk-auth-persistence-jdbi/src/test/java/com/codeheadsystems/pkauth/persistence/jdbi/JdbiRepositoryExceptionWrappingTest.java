// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.Transport;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.ChallengeRecord;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import com.codeheadsystems.pkauth.spi.PkAuthPersistenceException;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.Test;

/**
 * Unit tests asserting that every JDBI repo wraps native {@code JdbiException}s in {@link
 * PkAuthPersistenceException}. The shared SPI contract requires this so adapters can map a DB
 * outage to a single 503 response. We exercise the wrap branch by pointing JDBI at an unreachable
 * JDBC URL: every operation fails at connection time with a {@code ConnectionException} (a {@code
 * JdbiException} subclass), which the {@code wrap} helper must surface as a typed persistence
 * exception.
 */
class JdbiRepositoryExceptionWrappingTest {

  private static final String BAD_URL =
      "jdbc:postgresql://127.0.0.1:1/no_such_db?connectTimeout=1&socketTimeout=1";

  private static Jdbi badJdbi() {
    // JDBI lazily opens connections; calling any repository method against this Jdbi instance
    // raises a JdbiException at the first SQL execution.
    return Jdbi.create(BAD_URL, "pkauth", "pkauth");
  }

  @Test
  void credentialRepoWrapsConnectionFailure() {
    JdbiCredentialRepository repo = new JdbiCredentialRepository(badJdbi());
    UserHandle user = UserHandle.random();
    CredentialRecord rec =
        new CredentialRecord(
            CredentialId.of(new byte[] {1, 2, 3, 4}),
            user,
            new byte[] {9, 9, 9},
            0L,
            "label",
            UUID.randomUUID(),
            EnumSet.noneOf(Transport.class),
            true,
            false,
            Instant.parse("2026-05-15T00:00:00Z"),
            null);

    assertThatThrownBy(() -> repo.save(rec))
        .isInstanceOf(PkAuthPersistenceException.class)
        .extracting("operation")
        .isEqualTo("credentials.save");
    assertThatThrownBy(() -> repo.findByCredentialId(CredentialId.of(new byte[] {1})))
        .isInstanceOf(PkAuthPersistenceException.class);
    assertThatThrownBy(() -> repo.findByUserHandle(user))
        .isInstanceOf(PkAuthPersistenceException.class);
    assertThatThrownBy(
            () ->
                repo.updateSignCount(
                    CredentialId.of(new byte[] {1}), 5L, Instant.parse("2026-05-15T00:00:00Z")))
        .isInstanceOf(PkAuthPersistenceException.class);
    assertThatThrownBy(() -> repo.updateLabel(user, CredentialId.of(new byte[] {1}), "x"))
        .isInstanceOf(PkAuthPersistenceException.class);
    assertThatThrownBy(() -> repo.delete(user, CredentialId.of(new byte[] {1})))
        .isInstanceOf(PkAuthPersistenceException.class);
  }

  @Test
  void otpRepoWrapsConnectionFailure() {
    JdbiOtpRepository repo = new JdbiOtpRepository(badJdbi());
    UserHandle user = UserHandle.random();
    OtpRepository.StoredOtp record =
        new OtpRepository.StoredOtp(
            "o1",
            user,
            "+15551112222",
            "hash",
            0,
            5,
            false,
            Instant.parse("2026-05-15T00:00:00Z"),
            Instant.parse("2026-05-15T00:05:00Z"));
    assertThatThrownBy(() -> repo.save(record))
        .isInstanceOf(PkAuthPersistenceException.class)
        .extracting("operation")
        .isEqualTo("otp.save");
    assertThatThrownBy(
            () ->
                repo.findLatestActive(user, "+15551112222", Instant.parse("2026-05-15T00:00:00Z")))
        .isInstanceOf(PkAuthPersistenceException.class);
    assertThatThrownBy(() -> repo.incrementAttempts(user, "o1"))
        .isInstanceOf(PkAuthPersistenceException.class);
    assertThatThrownBy(() -> repo.consume(user, "o1"))
        .isInstanceOf(PkAuthPersistenceException.class);
    assertThatThrownBy(
            () -> repo.countSince(user, "+15551112222", Instant.parse("2026-05-15T00:00:00Z")))
        .isInstanceOf(PkAuthPersistenceException.class);
  }

  @Test
  void backupCodeRepoWrapsConnectionFailure() {
    JdbiBackupCodeRepository repo = new JdbiBackupCodeRepository(badJdbi());
    UserHandle user = UserHandle.random();
    Instant now = Instant.parse("2026-05-15T00:00:00Z");
    BackupCodeRepository.StoredBackupCode record =
        new BackupCodeRepository.StoredBackupCode("c1", user, "hash", false, now, null);
    assertThatThrownBy(() -> repo.save(record))
        .isInstanceOf(PkAuthPersistenceException.class)
        .extracting("operation")
        .isEqualTo("backupCodes.save");
    assertThatThrownBy(() -> repo.findByUserHandle(user))
        .isInstanceOf(PkAuthPersistenceException.class);
    assertThatThrownBy(() -> repo.consume(user, "c1", now))
        .isInstanceOf(PkAuthPersistenceException.class);
    assertThatThrownBy(() -> repo.deleteByUserHandle(user))
        .isInstanceOf(PkAuthPersistenceException.class);
    assertThatThrownBy(() -> repo.replaceAll(user, List.of()))
        .isInstanceOf(PkAuthPersistenceException.class);
    assertThatThrownBy(() -> repo.recordVerifyFailure("c1", user))
        .isInstanceOf(PkAuthPersistenceException.class);
  }

  @Test
  void challengeStoreWrapsConnectionFailure() {
    JdbiChallengeStore store = new JdbiChallengeStore(badJdbi());
    ChallengeId id = ChallengeId.random();
    ChallengeRecord record =
        new ChallengeRecord(
            new byte[] {1, 2, 3},
            ChallengeRecord.Purpose.REGISTRATION,
            null,
            Instant.parse("2026-05-15T00:05:00Z"));
    assertThatThrownBy(() -> store.put(id, record, Duration.ofMinutes(5)))
        .isInstanceOf(PkAuthPersistenceException.class)
        .extracting("operation")
        .isEqualTo("challenges.put");
    assertThatThrownBy(() -> store.takeOnce(id)).isInstanceOf(PkAuthPersistenceException.class);
  }

  @Test
  void userLookupWrapsConnectionFailure() {
    JdbiUserLookup lookup = new JdbiUserLookup(badJdbi());
    UserHandle user = UserHandle.random();
    assertThatThrownBy(() -> lookup.findHandleByUsername("alice"))
        .isInstanceOf(PkAuthPersistenceException.class)
        .extracting("operation")
        .isEqualTo("users.findHandleByUsername");
    assertThatThrownBy(() -> lookup.findViewByHandle(user))
        .isInstanceOf(PkAuthPersistenceException.class);
    assertThatThrownBy(() -> lookup.getOrCreateHandle("alice"))
        .isInstanceOf(PkAuthPersistenceException.class);
    assertThatThrownBy(() -> lookup.register("alice", "Alice"))
        .isInstanceOf(PkAuthPersistenceException.class);
  }

  @Test
  void operationFieldIsAlwaysSet() {
    // Cross-check that the operation string is a non-empty repository.method identifier so
    // operators can pinpoint the failing call.
    JdbiOtpRepository repo = new JdbiOtpRepository(badJdbi());
    try {
      repo.save(
          new OtpRepository.StoredOtp(
              "o1",
              UserHandle.random(),
              "+15551112222",
              "h",
              0,
              5,
              false,
              Instant.parse("2026-05-15T00:00:00Z"),
              Instant.parse("2026-05-15T00:05:00Z")));
    } catch (PkAuthPersistenceException e) {
      assertThat(e.operation()).contains(".");
      assertThat(e.operation()).startsWith("otp.");
    }
  }
}
