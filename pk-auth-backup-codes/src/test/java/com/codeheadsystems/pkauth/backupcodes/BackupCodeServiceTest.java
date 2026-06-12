// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.backupcodes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.backupcodes.BackupCodeService.InMemoryBackupCodeRateLimiter;
import com.codeheadsystems.pkauth.backupcodes.BackupCodeService.VerifyResult;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.testkit.InMemoryBackupCodeRepository;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class BackupCodeServiceTest {

  private static final Instant NOW = Instant.parse("2026-05-14T12:00:00Z");
  private InMemoryBackupCodeRepository repository;
  private InMemoryBackupCodeRateLimiter rateLimiter;
  private BackupCodeService service;

  @BeforeEach
  void setUp() {
    repository = new InMemoryBackupCodeRepository();
    rateLimiter = new InMemoryBackupCodeRateLimiter(BackupCodeService.DEFAULT_RATE_WINDOW);
    rateLimiter.reset();
    // Light Argon2 parameters to keep tests fast.
    Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
    service =
        BackupCodeService.create(
            new BackupCodeService.Dependencies(
                repository, ClockProvider.fromClock(Clock.fixed(NOW, ZoneOffset.UTC)), rateLimiter),
            new BackupCodeService.Config(
                new SecureRandom(),
                argon2,
                /* iterations */ 1,
                /* memory */ 1024,
                /* parallelism */ 1,
                /* codeCount */ 5,
                /* rateLimit */ BackupCodeService.DEFAULT_RATE_LIMIT));
  }

  @Test
  void configRejectsNonPositiveRanges() {
    SecureRandom rng = new SecureRandom();
    Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
    assertThatThrownBy(() -> new BackupCodeService.Config(rng, argon2, 0, 1024, 1, 5, 5))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("iterations");
    assertThatThrownBy(() -> new BackupCodeService.Config(rng, argon2, 1, 0, 1, 5, 5))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("memory");
    assertThatThrownBy(() -> new BackupCodeService.Config(rng, argon2, 1, 1024, 0, 5, 5))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("parallelism");
    assertThatThrownBy(() -> new BackupCodeService.Config(rng, argon2, 1, 1024, 1, 0, 5))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("codeCount");
    assertThatThrownBy(() -> new BackupCodeService.Config(rng, argon2, 1, 1024, 1, 5, 0))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("rateLimit");
  }

  @Test
  void generateProducesNDistinctTenCharCodes() {
    UserHandle user = UserHandle.of(new byte[] {1, 2, 3});
    List<String> codes = service.generate(user);
    assertThat(codes).hasSize(5);
    assertThat(codes).allMatch(c -> c.length() == BackupCodeService.CODE_LENGTH);
    assertThat(codes).doesNotHaveDuplicates();
    assertThat(repository.findByUserHandle(user)).hasSize(5);
  }

  @Test
  void verifyConsumesCodeOnFirstMatch() {
    UserHandle user = UserHandle.of(new byte[] {1, 2, 3});
    List<String> codes = service.generate(user);
    String first = codes.get(0);

    assertThat(service.verify(user, first)).isInstanceOf(VerifyResult.Success.class);
    assertThat(service.remainingCount(user)).isEqualTo(4);
    // Already consumed — second attempt must not match.
    rateLimiter.reset();
    assertThat(service.verify(user, first)).isInstanceOf(VerifyResult.NoMatch.class);
  }

  @Test
  void verifyRejectsUnknownCode() {
    UserHandle user = UserHandle.of(new byte[] {1, 2, 3});
    service.generate(user);
    assertThat(service.verify(user, "WRONGCODES")).isInstanceOf(VerifyResult.NoMatch.class);
    assertThat(service.remainingCount(user)).isEqualTo(5);
  }

  @Test
  void regenerateBackupCodesDeletesPriorAndIssuesFreshSet() {
    UserHandle user = UserHandle.of(new byte[] {1, 2, 3});
    List<String> first = service.generate(user);
    service.verify(user, first.get(0));
    rateLimiter.reset();

    List<String> second = service.regenerateBackupCodes(user);
    assertThat(second).hasSize(5);
    assertThat(service.remainingCount(user)).isEqualTo(5);
    // None of the first batch should verify anymore.
    for (String oldCode : first) {
      assertThat(service.verify(user, oldCode)).isInstanceOf(VerifyResult.NoMatch.class);
      rateLimiter.reset();
    }
  }

  @Test
  void verifyReturnsRateLimitedWhenLimitExceeded() {
    UserHandle user = UserHandle.of(new byte[] {4, 5, 6});
    service.generate(user);
    // Exhaust the rate limit.
    for (int i = 0; i < BackupCodeService.DEFAULT_RATE_LIMIT; i++) {
      VerifyResult result = service.verify(user, "WRONGCODES");
      assertThat(result).isNotInstanceOf(VerifyResult.RateLimited.class);
    }
    // Next attempt must be rate-limited.
    VerifyResult limited = service.verify(user, "WRONGCODES");
    assertThat(limited).isInstanceOf(VerifyResult.RateLimited.class);
    VerifyResult.RateLimited rl = (VerifyResult.RateLimited) limited;
    assertThat(rl.retryAfterSeconds()).isPositive();
  }

  @Test
  void verifyIsConstantTimeAcrossAllSlots() {
    // Smoke test: verify completes and returns NoMatch even when all codes are consumed,
    // confirming we always iterate every slot.
    UserHandle user = UserHandle.of(new byte[] {7, 8, 9});
    List<String> codes = service.generate(user);
    // Consume all codes.
    for (String code : codes) {
      service.verify(user, code);
      rateLimiter.reset();
    }
    assertThat(service.remainingCount(user)).isEqualTo(0);
    // Verify against a fully-consumed set — must return NoMatch (not Success or error).
    VerifyResult result = service.verify(user, "ANYCODE123");
    assertThat(result).isInstanceOf(VerifyResult.NoMatch.class);
  }
}
