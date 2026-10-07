// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.jwt.AccessTokenStore;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Shared parity scenarios for {@link AccessTokenStore} implementations. Driven from {@code
 * InMemoryAccessTokenStoreTest}, JDBI integration tests, and DynamoDB integration tests so every
 * backend behaves identically.
 *
 * <p>Each scenario runs from a {@code @Test} method against a fresh, empty store passed to the
 * constructor.
 *
 * @since 1.1.0
 */
public final class AccessTokenStoreScenarios {

  private static final Instant NOW = Instant.parse("2026-05-16T12:00:00Z");

  private final AccessTokenStore store;

  public AccessTokenStoreScenarios(AccessTokenStore store) {
    this.store = Objects.requireNonNull(store, "store");
  }

  /** Round-trip: record, observe via exists, then delete. */
  public void recordThenExistsThenDelete() {
    UserHandle user = UserHandle.of(new byte[] {1, 2, 3});
    store.record("jti-A", user, "web", Optional.empty(), NOW, NOW.plusSeconds(900));
    assertThat(store.exists("jti-A")).isTrue();
    assertThat(store.delete(user, "jti-A")).isTrue();
    assertThat(store.exists("jti-A")).isFalse();
    // delete is idempotent
    assertThat(store.delete(user, "jti-A")).isFalse();
  }

  /**
   * Ownership mismatch is a silent no-op; the caller cannot probe for jti existence across users.
   */
  public void deleteRejectsForeignOwner() {
    UserHandle alice = UserHandle.of(new byte[] {1});
    UserHandle bob = UserHandle.of(new byte[] {2});
    store.record("alice-jti", alice, "web", Optional.empty(), NOW, NOW.plusSeconds(900));
    assertThat(store.delete(bob, "alice-jti")).isFalse();
    assertThat(store.exists("alice-jti")).isTrue();
  }

  /** Unknown jti always returns false from exists. */
  public void existsReturnsFalseForUnknownJti() {
    assertThat(store.exists("never-recorded")).isFalse();
  }

  /** deleteAllForUser removes every jti owned by the supplied user, leaves other users intact. */
  public void deleteAllForUserRemovesEveryRow() {
    UserHandle alice = UserHandle.of(new byte[] {1});
    UserHandle bob = UserHandle.of(new byte[] {2});
    store.record("a1", alice, "web", Optional.empty(), NOW, NOW.plusSeconds(900));
    store.record("a2", alice, "cli", Optional.of("dev-1"), NOW, NOW.plusSeconds(3600));
    store.record("b1", bob, "web", Optional.empty(), NOW, NOW.plusSeconds(900));

    int removed = store.deleteAllForUser(alice);

    assertThat(removed).isEqualTo(2);
    assertThat(store.exists("a1")).isFalse();
    assertThat(store.exists("a2")).isFalse();
    assertThat(store.exists("b1")).isTrue();
  }

  /** deleteExpiredBefore removes only rows whose expires_at is strictly less than the cutoff. */
  public void deleteExpiredBeforePrunesOnlyExpiredRows() {
    UserHandle user = UserHandle.of(new byte[] {1});
    store.record("expired", user, "web", Optional.empty(), NOW, NOW.plusSeconds(60));
    store.record("still-valid", user, "web", Optional.empty(), NOW, NOW.plusSeconds(3600));

    int pruned = store.deleteExpiredBefore(NOW.plusSeconds(120));

    assertThat(pruned).isEqualTo(1);
    assertThat(store.exists("expired")).isFalse();
    assertThat(store.exists("still-valid")).isTrue();
  }

  /** Recording the same jti twice replaces the prior row (idempotent overwrite). */
  public void recordIsIdempotent() {
    UserHandle user = UserHandle.of(new byte[] {1});
    store.record("jti-X", user, "web", Optional.empty(), NOW, NOW.plusSeconds(900));
    store.record("jti-X", user, "cli", Optional.of("dev-1"), NOW, NOW.plusSeconds(3600));
    assertThat(store.exists("jti-X")).isTrue();
  }
}
