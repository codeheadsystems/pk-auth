// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository.StoredBackupCode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Backend-agnostic acceptance scenarios for {@link BackupCodeRepository}, focused on the atomic
 * single-use ({@code consume}) contract. Run against the in-memory testkit repo and every real
 * backend (JDBI, DynamoDB) so the double-spend guarantee — a recovery code can be redeemed at most
 * once — cannot regress in one implementation while passing in another. Mirrors {@link
 * RefreshTokenScenarios}'s concurrent rotation race for the refresh-token path.
 *
 * @since 1.3.1
 */
public final class BackupCodeRepositoryScenarios {

  private final BackupCodeRepository repository;

  public BackupCodeRepositoryScenarios(BackupCodeRepository repository) {
    this.repository = repository;
  }

  /**
   * The consume-once race: eight threads call {@link BackupCodeRepository#consume} on the same
   * freshly-saved code. Exactly one must win (return {@code true}); the rest must observe {@code
   * false}, and a follow-up consume must also be {@code false}. A regression from an atomic
   * conditional update to a read-modify-write would let two threads both redeem the same recovery
   * code.
   *
   * @throws Exception if a worker thread is interrupted.
   * @since 1.3.1
   */
  public void concurrentConsumeYieldsExactlyOneWinner() throws Exception {
    UserHandle user = UserHandle.random();
    Instant now = Instant.parse("2026-05-14T12:00:00Z");
    String codeId = "tck-concurrent-backup-code";
    repository.save(new StoredBackupCode(codeId, user, "hash", false, now, null));

    int threads = 8;
    CountDownLatch ready = new CountDownLatch(threads);
    CountDownLatch fire = new CountDownLatch(1);
    AtomicInteger winners = new AtomicInteger();
    try (ExecutorService pool = Executors.newFixedThreadPool(threads)) {
      List<Future<?>> futures = new ArrayList<>();
      for (int i = 0; i < threads; i++) {
        futures.add(
            pool.submit(
                () -> {
                  ready.countDown();
                  try {
                    fire.await();
                  } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(e);
                  }
                  if (repository.consume(user, codeId, now)) {
                    winners.incrementAndGet();
                  }
                }));
      }
      assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
      fire.countDown();
      for (Future<?> f : futures) {
        f.get(10, TimeUnit.SECONDS);
      }
      assertThat(winners.get()).as("exactly one thread consumes the backup code").isEqualTo(1);
      assertThat(repository.consume(user, codeId, now)).as("nothing left after the race").isFalse();
    }
  }
}
