// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.UserLookup.UserView;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Covers {@link DynamoDbUserLookup}'s registration / lookup surface — {@code getOrCreateHandle}
 * (create + idempotent re-fetch), {@code findHandleByUsername}, {@code register}, and {@code
 * findViewByHandle} — which the ceremony scenarios only touch via {@code getOrCreateHandle}.
 */
@Testcontainers
@DisabledIfEnvironmentVariable(named = "PKAUTH_SKIP_TESTCONTAINERS", matches = "1")
class DynamoDbUserLookupIntegrationTest {

  private DynamoDbUserLookup users;

  @BeforeEach
  void setUp() {
    var enhanced = DynamoDbLocalFixture.enhanced();
    var client = DynamoDbLocalFixture.client();
    String suffix = UUID.randomUUID().toString().substring(0, 8);
    PkAuthDynamoTables tables =
        new PkAuthDynamoTables("PkAuthCore_" + suffix, "PkAuthUsers_" + suffix);
    new DynamoDbSchemaBootstrapper(client, tables).bootstrap();
    users = new DynamoDbUserLookup(enhanced, tables);
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
  void concurrentGetOrCreateForSameUsernameConvergesOnOneHandle() throws Exception {
    int threads = 8;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    CountDownLatch start = new CountDownLatch(1);
    List<Future<UserHandle>> futures = new ArrayList<>();
    try {
      for (int i = 0; i < threads; i++) {
        futures.add(
            pool.submit(
                () -> {
                  start.await();
                  return users.getOrCreateHandle("erin");
                }));
      }
      start.countDown(); // release all threads at once to maximise the race window

      Set<UserHandle> distinct = new HashSet<>();
      for (Future<UserHandle> f : futures) {
        distinct.add(f.get());
      }
      // The username-uniqueness marker forces every racer to converge on exactly one handle...
      assertThat(distinct).hasSize(1);
      // ...and the persisted lookup resolves to that same single handle (no split identity).
      assertThat(users.findHandleByUsername("erin")).hasValue(distinct.iterator().next());
    } finally {
      pool.shutdownNow();
    }
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
