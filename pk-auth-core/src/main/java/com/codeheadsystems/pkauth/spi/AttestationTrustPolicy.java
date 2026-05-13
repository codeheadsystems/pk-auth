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
 */
public interface AttestationTrustPolicy {

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
