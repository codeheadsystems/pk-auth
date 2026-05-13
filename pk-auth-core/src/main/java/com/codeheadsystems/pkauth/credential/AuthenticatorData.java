// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.credential;

import java.util.Arrays;
import java.util.Objects;

/**
 * Parsed {@code authenticatorData} from a WebAuthn ceremony, exposing the byte array plus the flag
 * bits the relying party most often cares about. Phase 2 populates this from WebAuthn4J's parsed
 * structure.
 *
 * @param raw the original authenticator-data bytes (defensively copied)
 * @param userPresent {@code UP} flag
 * @param userVerified {@code UV} flag
 * @param backupEligible {@code BE} flag (synced-credential eligibility)
 * @param backupState {@code BS} flag (currently backed up)
 * @param attestedCredentialDataIncluded {@code AT} flag
 * @param extensionDataIncluded {@code ED} flag
 * @param signCount the authenticator's signature counter
 */
public record AuthenticatorData(
    byte[] raw,
    boolean userPresent,
    boolean userVerified,
    boolean backupEligible,
    boolean backupState,
    boolean attestedCredentialDataIncluded,
    boolean extensionDataIncluded,
    long signCount) {

  public AuthenticatorData {
    Objects.requireNonNull(raw, "raw");
    raw = raw.clone();
  }

  @Override
  public byte[] raw() {
    return raw.clone();
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof AuthenticatorData other
        && Arrays.equals(this.raw, other.raw)
        && this.userPresent == other.userPresent
        && this.userVerified == other.userVerified
        && this.backupEligible == other.backupEligible
        && this.backupState == other.backupState
        && this.attestedCredentialDataIncluded == other.attestedCredentialDataIncluded
        && this.extensionDataIncluded == other.extensionDataIncluded
        && this.signCount == other.signCount;
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(raw);
    result =
        31 * result
            + Objects.hash(
                userPresent,
                userVerified,
                backupEligible,
                backupState,
                attestedCredentialDataIncluded,
                extensionDataIncluded,
                signCount);
    return result;
  }

  @Override
  public String toString() {
    return "AuthenticatorData[signCount="
        + signCount
        + ", UP="
        + userPresent
        + ", UV="
        + userVerified
        + ", BE="
        + backupEligible
        + ", BS="
        + backupState
        + ", AT="
        + attestedCredentialDataIncluded
        + ", ED="
        + extensionDataIncluded
        + ", rawLen="
        + raw.length
        + "]";
  }
}
