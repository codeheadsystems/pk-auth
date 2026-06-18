// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.credential;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;

/**
 * Read-side helpers for reasoning about the COSE signature algorithm a stored credential uses.
 *
 * <p>WebAuthn4J records the algorithm <em>inside</em> the COSE-encoded public key ({@link
 * CredentialRecord#publicKeyCose()}), so the algorithm is already persisted on every credential —
 * there is no separate column and no schema change is needed to read it. This lets an operator
 * answer "which stored credentials use a (Shor-vulnerable) algorithm I want to migrate off?" and
 * drive a re-enrollment campaign, without expanding the {@code CredentialRepository} SPI.
 *
 * <p>The return value is the IANA COSE algorithm identifier (e.g. {@code -7} for ES256), matching
 * {@link com.codeheadsystems.pkauth.config.CoseAlgorithm#coseValue()} so callers can compare
 * against the configured algorithm vocabulary directly. See {@code docs/threat-model.md}
 * (Post-quantum readiness) and ADR 0019.
 *
 * @since 2.0.1
 */
public final class CredentialAlgorithms {

  // ObjectConverter is documented as reusable/thread-safe; one shared instance for read-side
  // decode.
  private static final ObjectConverter OBJECT_CONVERTER = new ObjectConverter();

  private CredentialAlgorithms() {}

  /**
   * Decodes the COSE algorithm identifier recorded in the credential's stored public key.
   *
   * @param record the stored credential.
   * @return the IANA COSE algorithm identifier (e.g. {@code -7} for ES256).
   * @throws IllegalStateException if the stored COSE key cannot be decoded or carries no algorithm.
   * @since 2.0.1
   */
  public static int coseAlgorithm(CredentialRecord record) {
    COSEKey coseKey;
    try {
      coseKey = OBJECT_CONVERTER.getCborMapper().readValue(record.publicKeyCose(), COSEKey.class);
    } catch (RuntimeException ex) {
      throw new IllegalStateException(
          "Unable to decode stored COSE key for credential " + record.credentialId(), ex);
    }
    COSEAlgorithmIdentifier alg = coseKey.getAlgorithm();
    if (alg == null) {
      throw new IllegalStateException(
          "Stored COSE key for credential " + record.credentialId() + " carries no algorithm");
    }
    return (int) alg.getValue();
  }

  /**
   * Reports whether the credential's stored public key uses the supplied COSE algorithm identifier.
   *
   * @param record the stored credential.
   * @param coseAlgorithm the IANA COSE algorithm identifier to test for (e.g. {@code -7} for
   *     ES256).
   * @return {@code true} if the credential uses that algorithm.
   * @since 2.0.1
   */
  public static boolean usesAlgorithm(CredentialRecord record, int coseAlgorithm) {
    return coseAlgorithm(record) == coseAlgorithm;
  }
}
