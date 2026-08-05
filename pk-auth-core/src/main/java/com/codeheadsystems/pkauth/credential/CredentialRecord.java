// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.credential;

import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.Transport;
import com.codeheadsystems.pkauth.api.UserHandle;
import java.time.Instant;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.jspecify.annotations.Nullable;

/**
 * Stored credential associated with a user handle. Persisted by {@code CredentialRepository}
 * implementations.
 *
 * @param credentialId WebAuthn credential id (opaque value type)
 * @param userHandle the user this credential authenticates
 * @param publicKeyCose the COSE-encoded public key (defensively copied)
 * @param signCount the latest known authenticator signature counter
 * @param label human-readable label, e.g. "Work laptop"
 * @param aaguid the AAGUID of the authenticator that created this credential (nullable for
 *     pre-FIDO2 credentials or where unknown)
 * @param transports the {@code AuthenticatorTransport} values the authenticator advertises
 * @param backupEligible authenticator-reported BE flag
 * @param backupState authenticator-reported BS flag
 * @param createdAt when the credential was registered
 * @param lastUsedAt when the credential was last used in a successful assertion; null if never
 * @since 0.9.0
 */
public record CredentialRecord(
    CredentialId credentialId,
    UserHandle userHandle,
    byte[] publicKeyCose,
    long signCount,
    String label,
    @Nullable UUID aaguid,
    Set<Transport> transports,
    boolean backupEligible,
    boolean backupState,
    Instant createdAt,
    @Nullable Instant lastUsedAt) {

  /**
   * Maximum accepted length of {@link #label}, in {@code char}s.
   *
   * <p>The label is the one free-text, host-visible field an unauthenticated caller controls (set
   * at {@code register/finish}, changed via {@code PATCH /auth/admin/credentials/{id}}) and it is
   * persisted and echoed back by {@code AdminService.listCredentials}. Bounding it keeps an
   * arbitrarily large blob out of storage and out of every UI that renders a credential list. It is
   * a nickname ("Work laptop", "MacBook Touch ID"), so 64 is generous.
   *
   * <p>This is a length bound only — it is <em>not</em> an escaping mechanism. A label is untrusted
   * text: renderers MUST escape it for their output context (see the demos' credential list, which
   * builds DOM nodes with {@code textContent} rather than interpolating into {@code innerHTML}).
   *
   * @since 2.3.0
   */
  public static final int MAX_LABEL_LENGTH = 64;

  public CredentialRecord {
    Objects.requireNonNull(credentialId, "credentialId");
    Objects.requireNonNull(userHandle, "userHandle");
    Objects.requireNonNull(publicKeyCose, "publicKeyCose");
    if (publicKeyCose.length == 0) {
      throw new IllegalArgumentException("publicKeyCose must be non-empty");
    }
    if (signCount < 0) {
      throw new IllegalArgumentException("signCount must be non-negative");
    }
    Objects.requireNonNull(label, "label");
    Objects.requireNonNull(transports, "transports");
    Objects.requireNonNull(createdAt, "createdAt");
    publicKeyCose = publicKeyCose.clone();
    transports =
        transports.isEmpty() ? EnumSet.noneOf(Transport.class) : EnumSet.copyOf(transports);
  }

  @Override
  public byte[] publicKeyCose() {
    return publicKeyCose.clone();
  }

  /** Read-only projection without the public key material. */
  public CredentialMetadata toMetadata() {
    return new CredentialMetadata(
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
  public boolean equals(Object o) {
    return o instanceof CredentialRecord other
        && this.credentialId.equals(other.credentialId)
        && this.userHandle.equals(other.userHandle)
        && Arrays.equals(this.publicKeyCose, other.publicKeyCose)
        && this.signCount == other.signCount
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
    int result = credentialId.hashCode();
    result =
        31 * result
            + Objects.hash(
                userHandle,
                Arrays.hashCode(publicKeyCose),
                signCount,
                label,
                aaguid,
                transports,
                backupEligible,
                backupState,
                createdAt,
                lastUsedAt);
    return result;
  }

  @Override
  public String toString() {
    return "CredentialRecord[credentialId="
        + credentialId
        + ", userHandle="
        + userHandle
        + ", signCount="
        + signCount
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
