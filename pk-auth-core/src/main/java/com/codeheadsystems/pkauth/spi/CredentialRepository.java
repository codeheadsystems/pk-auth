// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Persistent storage for passkey credentials. Implemented by the JDBI and DynamoDB persistence
 * modules (and by {@code InMemoryEverything} in the testkit).
 */
public interface CredentialRepository {

  /** Inserts a new credential record. Implementations must reject duplicates on credentialId. */
  void save(CredentialRecord record);

  Optional<CredentialRecord> findByCredentialId(byte[] credentialId);

  List<CredentialRecord> findByUserHandle(UserHandle userHandle);

  void updateSignCount(byte[] credentialId, long newCount, Instant lastUsedAt);

  void updateLabel(byte[] credentialId, String label);

  void delete(byte[] credentialId);
}
