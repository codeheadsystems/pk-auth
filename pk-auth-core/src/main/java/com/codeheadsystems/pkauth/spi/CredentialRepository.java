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

  /**
   * Inserts a new credential record. Implementations MUST reject a duplicate {@code credentialId}
   * by throwing {@link DuplicateCredentialException} rather than overwriting the existing row — a
   * duplicate at registration-finish is a replay/clobber attempt, not an update.
   *
   * @param record the credential to persist.
   * @throws DuplicateCredentialException if a credential with the same {@code credentialId} exists.
   * @since 0.9.0
   */
  void save(CredentialRecord record);

  /**
   * Looks up a credential by its (globally unique) {@code credentialId}.
   *
   * @param credentialId the credential to find.
   * @return the credential, or {@link Optional#empty()} if no row matches.
   * @since 0.9.0
   */
  Optional<CredentialRecord> findByCredentialId(CredentialId credentialId);

  /**
   * Lists every credential owned by the supplied user, in unspecified order.
   *
   * @param userHandle the owner.
   * @return the user's credentials, or an empty list if the user has none (never {@code null}).
   * @since 0.9.0
   */
  List<CredentialRecord> findByUserHandle(UserHandle userHandle);

  /**
   * Updates the stored signature counter and last-used timestamp after a successful assertion. This
   * is a last-writer-wins overwrite of the two fields (no compare-and-set); the WebAuthn4J counter
   * verification that authorizes the new value runs in the service before this call. A missing row
   * is a silent no-op.
   *
   * @param credentialId the credential that just authenticated.
   * @param newCount the new signature counter to store.
   * @param lastUsedAt when the assertion occurred.
   * @since 0.9.0
   */
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
