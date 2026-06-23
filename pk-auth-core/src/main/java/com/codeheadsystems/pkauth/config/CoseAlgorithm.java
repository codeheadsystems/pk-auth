// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.config;

/**
 * The COSE signature algorithms pk-auth can offer to an authenticator and accept on a passkey
 * registration. This is the single, framework-neutral vocabulary that both the create-options
 * ceremony and the WebAuthn4J verification path map from (see {@link CeremonyConfig}); it replaces
 * the two formerly-divergent hardcoded lists.
 *
 * <p>Each constant carries its <a href="https://www.iana.org/assignments/cose/cose.xhtml">IANA COSE
 * algorithm identifier</a> (the negative integer that appears as label {@code 3} in a COSE key and
 * in {@code PublicKeyCredentialParameters.alg} on the wire).
 *
 * <p><strong>Post-quantum note.</strong> Every algorithm here (ECDSA, EdDSA, RSA-PKCS1) is
 * Shor-vulnerable. No post-quantum signature scheme is yet standardized in the WebAuthn/COSE/FIDO2
 * stack or implemented by WebAuthn4J, so none can be added today. This enum is the seam through
 * which a quantum-safe COSE algorithm would be introduced once the ecosystem supports it — without
 * touching the ceremony or verification code. See {@code docs/threat-model.md} (Post-quantum
 * readiness) and ADR 0019.
 *
 * @since 2.1.0
 */
public enum CoseAlgorithm {

  /** ECDSA with SHA-256 over P-256 (COSE {@code -7}). The near-universal passkey default. */
  ES256(-7),

  /** EdDSA (Ed25519) (COSE {@code -8}). */
  EdDSA(-8),

  /** ECDSA with SHA-384 over P-384 (COSE {@code -35}). */
  ES384(-35),

  /** RSASSA-PKCS1-v1_5 with SHA-256 (COSE {@code -257}). */
  RS256(-257),

  /** RSASSA-PKCS1-v1_5 with SHA-384 (COSE {@code -258}). */
  RS384(-258);

  private final int coseValue;

  CoseAlgorithm(int coseValue) {
    this.coseValue = coseValue;
  }

  /**
   * The IANA COSE algorithm identifier for this algorithm (e.g. {@code -7} for {@link #ES256}).
   *
   * @return the signed COSE algorithm identifier.
   * @since 2.1.0
   */
  public int coseValue() {
    return coseValue;
  }
}
