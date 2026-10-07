// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.Transport;
import com.codeheadsystems.pkauth.credential.CredentialMetadata;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.jspecify.annotations.Nullable;

/**
 * Wire-shape projection of a credential for the credential-management endpoints. Mirrors {@link
 * CredentialMetadata} but lives in the admin module so the wire schema is owned here.
 *
 * <p>The {@code credentialId} field is the type-safe {@link CredentialId} value class (was raw
 * {@code byte[]} prior to 0.9.1). Wire JSON is unchanged: {@link CredentialId} has a Jackson
 * (de)serialiser registered in {@code PkAuthObjectMappers} that emits a base64url string, matching
 * the historical {@code byte[]} encoding.
 *
 * @since 0.9.1
 */
public record CredentialSummary(
    CredentialId credentialId,
    String label,
    @Nullable UUID aaguid,
    Set<String> transports,
    boolean backupEligible,
    boolean backupState,
    Instant createdAt,
    @Nullable Instant lastUsedAt) {

  public CredentialSummary {
    Objects.requireNonNull(credentialId, "credentialId");
    Objects.requireNonNull(label, "label");
    Objects.requireNonNull(transports, "transports");
    Objects.requireNonNull(createdAt, "createdAt");
    transports = Set.copyOf(transports);
  }

  /** Builds a summary from a stored {@link CredentialRecord}. */
  public static CredentialSummary of(CredentialRecord r) {
    Set<String> wireTransports = new LinkedHashSet<>();
    for (Transport t : r.transports()) {
      wireTransports.add(t.wireName());
    }
    return new CredentialSummary(
        r.credentialId(),
        r.label(),
        r.aaguid(),
        wireTransports,
        r.backupEligible(),
        r.backupState(),
        r.createdAt(),
        r.lastUsedAt());
  }
}
