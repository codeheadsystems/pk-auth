// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.lifecycle;

import com.codeheadsystems.pkauth.api.UserHandle;

/**
 * Hook invoked by {@link UserDeletionService} for each registered listener when a user is being
 * deleted. Implementations are typically thin adapters around a repository / store, deleting all
 * rows owned by the supplied {@link UserHandle}.
 *
 * <p>Contract:
 *
 * <ul>
 *   <li>Idempotent: a listener may be invoked more than once for the same user (e.g. a retry after
 *       a transient failure). Calls must converge on "all rows for this user are absent" without
 *       throwing on second-and-later invocations.
 *   <li>Best-effort isolated: each listener runs in its own scope; failures are logged and the
 *       service continues with remaining listeners. Listeners must not assume earlier listeners
 *       succeeded.
 * </ul>
 *
 * <p>See ADR 0016 for the rationale behind the sequential-per-listener (rather than
 * single-shared-transaction) fan-out.
 *
 * @since 1.1.0
 */
@FunctionalInterface
public interface UserDeletionListener {

  /**
   * Invoked once per registered listener when {@link UserDeletionService#deleteUser(UserHandle)}
   * runs. Implementations must delete every row owned by the supplied user from their backing
   * store.
   *
   * @param userHandle the user whose state is being removed
   * @throws RuntimeException any failure; the service catches, logs, and proceeds to the next
   *     listener
   */
  void onUserDeleted(UserHandle userHandle);

  /**
   * Display name for structured logging and {@link UserDeletionResult} reporting. Defaults to the
   * implementing class's simple name.
   */
  default String name() {
    return getClass().getSimpleName();
  }
}
