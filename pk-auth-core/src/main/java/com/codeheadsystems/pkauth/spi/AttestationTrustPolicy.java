// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import com.codeheadsystems.pkauth.api.AttestationConveyance;
import java.util.Objects;
import java.util.UUID;
import org.jspecify.annotations.Nullable;

/**
 * Pluggable attestation trust policy. The default {@code none()} accepts any attestation
 * (appropriate for consumer passkeys); custom implementations can plug in MDS3 / metadata-service
 * validation.
 *
 * <p><strong>Attestation-statement guarantees:</strong> pk-auth wires webauthn4j in non-strict mode
 * for registration. When the relying party requests {@link AttestationConveyance#NONE} (the library
 * default for consumer passkeys), webauthn4j does <em>not</em> cryptographically verify the
 * attestation statement — the {@link AttestationData#format() format} field handed to a policy is
 * informational only, supplied by the authenticator and not cross-checked against a trust chain. A
 * policy that needs cryptographic provenance (e.g. enterprise enrolment, MDS3 attestation
 * verification) MUST request {@link AttestationConveyance#DIRECT} (or stricter) via {@code
 * RelyingPartyConfig} so the underlying WebAuthn manager runs the format-specific verifier. Until
 * that happens, treat {@code format} as untrusted metadata.
 *
 * @since 0.9.0
 */
public interface AttestationTrustPolicy {

  /**
   * Evaluates the attestation presented during registration and decides whether to trust it.
   *
   * @param data the parsed attestation material for the registering credential.
   * @return a {@link Decision} — trusted, or rejected with a reason.
   * @since 0.9.0
   */
  Decision evaluate(AttestationData data);

  /** Policy that accepts any attestation. */
  static AttestationTrustPolicy none() {
    return data -> new Decision.Trusted();
  }

  /** Input handed to the policy for evaluation. AAGUID and format may be null when unknown. */
  record AttestationData(
      @Nullable UUID aaguid, @Nullable String format, AttestationConveyance conveyance) {
    public AttestationData {
      Objects.requireNonNull(conveyance, "conveyance");
    }
  }

  /** Closed sum of policy outcomes. */
  sealed interface Decision {
    record Trusted() implements Decision {}

    record Rejected(String reason) implements Decision {
      public Rejected {
        Objects.requireNonNull(reason, "reason");
      }
    }
  }
}
