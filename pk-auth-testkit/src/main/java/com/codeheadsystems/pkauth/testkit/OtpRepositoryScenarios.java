// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import com.codeheadsystems.pkauth.spi.OtpRepository.StoredOtp;
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
 * Backend-agnostic acceptance scenarios for {@link OtpRepository}, focused on the atomic single-use
 * ({@code consume}) contract. Run against the in-memory testkit repo and every real backend (JDBI,
 * DynamoDB) so the double-spend guarantee — an OTP can be verified at most once — cannot regress in
 * one implementation while passing in another. Mirrors {@link RefreshTokenScenarios}'s concurrent
 * rotation race for the refresh-token path.
 *
 * @since 2.0.0
 */
public final class OtpRepositoryScenarios {

  private static final String PHONE = "+15551230000";

  private final OtpRepository repository;

  public OtpRepositoryScenarios(OtpRepository repository) {
    this.repository = repository;
  }

  /**
   * The consume-once race: eight threads call {@link OtpRepository#consume} on the same
   * freshly-saved OTP. Exactly one must win (return {@code true}); the rest must observe {@code
   * false}, and a follow-up consume must also be {@code false}. A regression from an atomic
   * conditional update to a read-modify-write would let two threads both "consume" the same code,
   * enabling OTP reuse.
   *
   * @throws Exception if a worker thread is interrupted.
   * @since 2.0.0
   */
  public void concurrentConsumeYieldsExactlyOneWinner() throws Exception {
    UserHandle user = UserHandle.random();
    Instant now = Instant.parse("2026-05-14T12:00:00Z");
    String otpId = "tck-concurrent-otp";
    repository.save(
        new StoredOtp(otpId, user, PHONE, "hash", 0, 5, false, now, now.plusSeconds(300)));

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
                  if (repository.consume(user, otpId)) {
                    winners.incrementAndGet();
                  }
                }));
      }
      assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
      fire.countDown();
      for (Future<?> f : futures) {
        f.get(10, TimeUnit.SECONDS);
      }
      assertThat(winners.get()).as("exactly one thread consumes the OTP").isEqualTo(1);
      assertThat(repository.consume(user, otpId)).as("nothing left after the race").isFalse();
    }
  }
}
