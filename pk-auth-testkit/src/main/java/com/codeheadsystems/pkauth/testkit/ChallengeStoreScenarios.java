// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.ChallengeRecord;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Shared compliance scenarios for {@link ChallengeStore} implementations — the single-use contract
 * every backend (in-memory, JDBI, DynamoDB) must honour. {@link ChallengeStore#takeOnce} is the
 * load-bearing primitive behind WebAuthn replay defense: a challenge must be consumable exactly
 * once, even under concurrent finish requests, or an assertion could be replayed.
 *
 * <p>Drive these from each backend's test class (passing a fresh, empty store) so the atomic
 * read-and-remove contract is verified identically everywhere, not just asserted single-threaded.
 *
 * @since 1.3.0
 */
public final class ChallengeStoreScenarios {

  private static final UserHandle USER = UserHandle.of(new byte[] {4, 2});
  private static final byte[] CHALLENGE = new byte[32];

  private final ChallengeStore store;

  public ChallengeStoreScenarios(ChallengeStore store) {
    this.store = Objects.requireNonNull(store, "store");
  }

  /** takeOnce returns the record the first time and empty every time after. */
  public void takeOnceConsumesExactlyOnce() {
    ChallengeId id = new ChallengeId("tck-single-use");
    store.put(id, record(), Duration.ofMinutes(5));
    assertThat(store.takeOnce(id)).as("first take wins").isPresent();
    assertThat(store.takeOnce(id)).as("second take is consumed").isEmpty();
  }

  /**
   * The non-negotiable atomicity test: N threads call {@link ChallengeStore#takeOnce} on the same
   * id simultaneously and exactly one must receive the record. A non-atomic read-then-delete would
   * let two threads both observe and "consume" the same challenge, enabling assertion replay.
   */
  public void concurrentTakeOnceYieldsExactlyOneWinner() throws Exception {
    ChallengeId id = new ChallengeId("tck-concurrent-take-once");
    store.put(id, record(), Duration.ofMinutes(5));

    int threads = 8;
    CountDownLatch ready = new CountDownLatch(threads);
    CountDownLatch fire = new CountDownLatch(1);
    AtomicInteger winners = new AtomicInteger();
    try (ExecutorService pool = Executors.newFixedThreadPool(threads)) {
      List<Future<?>> futures = new java.util.ArrayList<>();
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
                  Optional<ChallengeRecord> taken = store.takeOnce(id);
                  if (taken.isPresent()) {
                    winners.incrementAndGet();
                  }
                }));
      }
      assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
      fire.countDown();
      for (Future<?> f : futures) {
        f.get(10, TimeUnit.SECONDS);
      }
      assertThat(winners.get()).as("exactly one thread consumes the challenge").isEqualTo(1);
      assertThat(store.takeOnce(id)).as("nothing left after the race").isEmpty();
    }
  }

  private static ChallengeRecord record() {
    return new ChallengeRecord(
        CHALLENGE,
        ChallengeRecord.Purpose.AUTHENTICATION,
        USER,
        Instant.now().plus(Duration.ofMinutes(5)));
  }
}
