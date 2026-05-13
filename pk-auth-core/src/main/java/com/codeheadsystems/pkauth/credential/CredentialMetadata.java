// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.credential;

import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.jspecify.annotations.Nullable;

/** Read-only credential projection without the COSE public key. Suitable for listing endpoints. */
public record CredentialMetadata(
    byte[] credentialId,
    String label,
    @Nullable UUID aaguid,
    Set<String> transports,
    boolean backupEligible,
    boolean backupState,
    Instant createdAt,
    @Nullable Instant lastUsedAt) {

  public CredentialMetadata {
    Objects.requireNonNull(credentialId, "credentialId");
    if (credentialId.length == 0) {
      throw new IllegalArgumentException("credentialId must be non-empty");
    }
    Objects.requireNonNull(label, "label");
    Objects.requireNonNull(transports, "transports");
    Objects.requireNonNull(createdAt, "createdAt");
    credentialId = credentialId.clone();
    transports = Set.copyOf(transports);
  }

  @Override
  public byte[] credentialId() {
    return credentialId.clone();
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof CredentialMetadata other
        && Arrays.equals(this.credentialId, other.credentialId)
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
    int result = Arrays.hashCode(credentialId);
    result =
        31 * result
            + Objects.hash(
                label, aaguid, transports, backupEligible, backupState, createdAt, lastUsedAt);
    return result;
  }

  @Override
  public String toString() {
    return "CredentialMetadata[credentialId="
        + HexFormat.of().formatHex(credentialId)
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
