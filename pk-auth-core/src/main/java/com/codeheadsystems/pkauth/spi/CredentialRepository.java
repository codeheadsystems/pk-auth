// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Persistent storage for passkey credentials. Implemented by the JDBI and DynamoDB persistence
 * modules (and by {@code InMemoryEverything} in the testkit).
 *
 * @since 0.9.0
 */
public interface CredentialRepository {

  /** Inserts a new credential record. Implementations must reject duplicates on credentialId. */
  void save(CredentialRecord record);

  Optional<CredentialRecord> findByCredentialId(CredentialId credentialId);

  List<CredentialRecord> findByUserHandle(UserHandle userHandle);

  void updateSignCount(CredentialId credentialId, long newCount, Instant lastUsedAt);

  /**
   * Renames the credential identified by {@code credentialId}, but only if it is owned by {@code
   * userHandle}. Implementations must include {@code user_handle} in the predicate so that a forged
   * or guessed credential id cannot be used to rename another user's credential — pure
   * defense-in-depth on top of the service-layer ownership check. A row mismatch is a silent no-op
   * (no exception); the caller has already established existence via {@code findByCredentialId}.
   */
  void updateLabel(UserHandle userHandle, CredentialId credentialId, String label);

  /**
   * Hard-deletes the credential row, but only if it is owned by {@code userHandle}. Implementations
   * must include {@code user_handle} in the predicate (defense in depth — see {@link
   * #updateLabel}). Soft-delete (e.g. a {@code revoked_at} marker) is not permitted on this SPI.
   *
   * <p>Audit history for credential deletions is the responsibility of the host's structured log
   * pipeline. pk-auth's {@code DefaultAdminService.deleteCredential} emits a {@code
   * pkauth.credential.deleted} INFO log event (containing the base64url credential id and user
   * handle) around every call to this method; consume that signal rather than persisting deletion
   * tombstones inside the credentials table.
   */
  void delete(UserHandle userHandle, CredentialId credentialId);

  /**
   * Hard-deletes every credential owned by the supplied user. Called by {@link
   * com.codeheadsystems.pkauth.lifecycle.UserDeletionService} during user-deletion fan-out; hosts
   * may also call it directly for bulk-revocation flows.
   *
   * <p>Returns the number of rows removed (best-effort; used for structured logging). Must be
   * idempotent — a call against a user with no remaining credentials returns {@code 0}.
   *
   * @since 1.1.0
   */
  int deleteByUserHandle(UserHandle userHandle);
}
