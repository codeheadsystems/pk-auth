// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.credential;

import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.Transport;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.jspecify.annotations.Nullable;

/**
 * Read-only credential projection without the COSE public key. Suitable for listing endpoints.
 *
 * @since 0.9.0
 */
public record CredentialMetadata(
    CredentialId credentialId,
    String label,
    @Nullable UUID aaguid,
    Set<Transport> transports,
    boolean backupEligible,
    boolean backupState,
    Instant createdAt,
    @Nullable Instant lastUsedAt) {

  public CredentialMetadata {
    Objects.requireNonNull(credentialId, "credentialId");
    Objects.requireNonNull(label, "label");
    Objects.requireNonNull(transports, "transports");
    Objects.requireNonNull(createdAt, "createdAt");
    transports =
        transports.isEmpty() ? EnumSet.noneOf(Transport.class) : EnumSet.copyOf(transports);
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof CredentialMetadata other
        && this.credentialId.equals(other.credentialId)
        && this.label.equals(other.label)
        && Objects.equals(this.aaguid, other.aaguid)
        && this.transports.equals(other.transports)
        && this.backupEligible == other.backupEligible
        && this.backupState == other.backupState
        && this.createdAt.equals(other.createdAt)
        && Objects.equals(this.lastUsedAt, other.lastUsedAt);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        credentialId,
        label,
        aaguid,
        transports,
        backupEligible,
        backupState,
        createdAt,
        lastUsedAt);
  }

  @Override
  public String toString() {
    return "CredentialMetadata[credentialId="
        + credentialId
        + ", label="
        + label
        + ", aaguid="
        + aaguid
        + ", transports="
        + transports
        + ", BE="
        + backupEligible
        + ", BS="
        + backupState
        + ", createdAt="
        + createdAt
        + ", lastUsedAt="
        + lastUsedAt
        + "]";
  }
}
