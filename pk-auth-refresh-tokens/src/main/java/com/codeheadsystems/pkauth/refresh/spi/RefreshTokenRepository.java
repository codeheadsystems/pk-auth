// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh.spi;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.refresh.RefreshTokenRecord;
import com.codeheadsystems.pkauth.refresh.RevokeReason;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Persistence SPI for {@link com.codeheadsystems.pkauth.refresh.RefreshTokenService}. Implemented
 * by:
 *
 * <ul>
 *   <li>{@code pk-auth-testkit}: in-memory, for unit tests / dev boots
 *   <li>{@code pk-auth-persistence-jdbi}: Postgres + Flyway V9
 *   <li>{@code pk-auth-persistence-dynamodb}: single-table on {@code PkAuthCore}
 * </ul>
 *
 * <p>Load-bearing replay defence: {@link #rotateAtomically(String, Instant, RefreshTokenRecord)}
 * must mark the parent used and insert the successor as a single atomic operation. Implementations
 * must not decompose this into a separate mark-then-insert sequence; a concurrent rotator's
 * family-scorch run between the two would miss the freshly-inserted successor. The service relies
 * on a {@code false} return to indicate "another caller already used or revoked this token" and
 * triggers a family-wide scorch in that branch.
 *
 * <p>See ADR 0013 for the design rationale.
 *
 * @since 1.1.0
 */
public interface RefreshTokenRepository {

  /**
   * Persists a freshly-issued or freshly-rotated refresh token. Implementations should reject a
   * duplicate {@code refreshId}; this is a server-side bug, not a normal operation.
   */
  void create(RefreshTokenRecord record);

  /** Returns the row identified by {@code refreshId}, or empty if no such row exists. */
  Optional<RefreshTokenRecord> findByRefreshId(String refreshId);

  /**
   * Atomic mark-and-insert: marks {@code parentRefreshId} used iff still fresh and inserts the
   * supplied {@code successor} row, as a single atomic operation. Returns {@code true} iff the
   * parent was fresh and the successor was inserted; {@code false} iff the parent was already used,
   * revoked, expired, or absent (no successor row created).
   *
   * <p>Load-bearing replay defence: the atomicity is the entire point; a non-atomic sequence (mark,
   * then insert) has a window where another concurrent rotator can call {@link #revokeFamily}
   * between the two and miss the newly-inserted successor. Backend implementations must use:
   *
   * <ul>
   *   <li>JDBI: {@code jdbi.inTransaction(handle -> {...})} wrapping a conditional {@code UPDATE}
   *       and the successor {@code INSERT}.
   *   <li>DynamoDB: {@code TransactWriteItems} with a conditional update on the parent item and a
   *       conditional put for the successor item.
   *   <li>In-memory: a synchronized region or {@code ConcurrentHashMap.compute} block.
   * </ul>
   *
   * <p>The predicate "fresh" means: {@code used_at IS NULL AND revoked_at IS NULL AND expires_at >
   * :now}. On {@code false}, the service triggers a family-wide scorch; that revoke runs outside
   * the failed rotation's scope so it commits regardless.
   *
   * @param parentRefreshId the {@code refreshId} of the token being rotated; its row must exist
   * @param now timestamp to write into {@code used_at} on success
   * @param successor the new row to insert iff the parent was fresh
   * @return {@code true} iff the rotation completed atomically; {@code false} iff the parent was
   *     not fresh
   */
  boolean rotateAtomically(String parentRefreshId, Instant now, RefreshTokenRecord successor);

  /**
   * Revokes every unrevoked row in {@code familyId} with the supplied reason. Idempotent;
   * already-revoked rows are left untouched (their original {@code revoked_reason} is preserved for
   * forensic visibility). Returns the number of rows newly marked revoked.
   */
  int revokeFamily(String familyId, Instant now, RevokeReason reason);

  /**
   * Revokes every unrevoked refresh-token row owned by {@code userHandle}. Used by the
   * user-deletion fan-out and admin "log out everywhere" actions. Idempotent. Returns the number of
   * rows newly marked revoked.
   */
  int revokeAllForUser(UserHandle userHandle, Instant now, RevokeReason reason);

  /** Lists every refresh-token row for a user. Read-only; used by admin / UI surfaces. */
  List<RefreshTokenRecord> findByUserHandle(UserHandle userHandle);

  /**
   * Lists every refresh-token row in {@code familyId}. Intended for tests and forensic inspection;
   * production code paths normally do not need this.
   */
  List<RefreshTokenRecord> findByFamilyId(String familyId);

  /**
   * Operator cleanup hook: deletes rows whose retention window has elapsed. Implementations should
   * remove rows where {@code expires_at < cutoff} and (the row is consumed or revoked before {@code
   * cutoff}). Returns the number of rows deleted. Documented in {@code docs/operator-guide.md}.
   */
  int deleteExpiredBefore(Instant cutoff);
}
