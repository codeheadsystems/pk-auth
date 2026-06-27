// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository.StoredBackupCode;
import com.codeheadsystems.pkauth.spi.OtpRepository.StoredOtp;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class InMemoryAltFlowRepositoriesTest {

  @Test
  void backupCodeRepositoryCrud() {
    InMemoryBackupCodeRepository repo = new InMemoryBackupCodeRepository();
    UserHandle user = UserHandle.random();
    Instant now = Instant.parse("2026-05-14T12:00:00Z");

    repo.save(new StoredBackupCode("c1", user, "h1", false, now, null));
    repo.save(new StoredBackupCode("c2", user, "h2", false, now, null));
    assertThat(repo.findByUserHandle(user)).hasSize(2);

    repo.consume(user, "c1", now.plusSeconds(60));
    assertThat(repo.findByUserHandle(user)).filteredOn(StoredBackupCode::consumed).hasSize(1);

    repo.deleteByUserHandle(user);
    assertThat(repo.findByUserHandle(user)).isEmpty();
  }

  @Test
  void otpRepositoryCrudAndCountSince() {
    InMemoryOtpRepository repo = new InMemoryOtpRepository();
    UserHandle user = UserHandle.random();
    Instant t0 = Instant.parse("2026-05-14T12:00:00Z");
    repo.save(new StoredOtp("o1", user, "+15551234567", "h", 0, 5, false, t0, t0.plusSeconds(300)));
    repo.save(
        new StoredOtp(
            "o2", user, "+15551234567", "h", 0, 5, false, t0.plusSeconds(60), t0.plusSeconds(360)));

    assertThat(repo.findLatestActive(user, "+15551234567", t0))
        .hasValueSatisfying(o -> assertThat(o.otpId()).isEqualTo("o2"));

    repo.incrementAttempts(user, "o2");
    repo.incrementAttempts(user, "o2");
    assertThat(repo.findLatestActive(user, "+15551234567", t0))
        .hasValueSatisfying(o -> assertThat(o.attempts()).isEqualTo(2));

    assertThat(repo.countSince(user, "+15551234567", t0.minusSeconds(10))).isEqualTo(2);
    assertThat(repo.countSince(user, "+15551234567", t0.plusSeconds(120))).isZero();

    repo.consume(user, "o2");
    assertThat(repo.findLatestActive(user, "+15551234567", t0))
        .hasValueSatisfying(o -> assertThat(o.otpId()).isEqualTo("o1"));
  }
}
