// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.error;

/**
 * Stable string codes that adapter modules map to HTTP error responses. Each code's string value is
 * the wire contract — do not rename without bumping the public API version.
 */
public enum PkAuthErrorCode {
  /** Internal misconfiguration detected at startup or during a ceremony. */
  CONFIGURATION("pkauth.configuration"),

  /** Ceremony state was used in an unsupported way (programmer error). */
  ILLEGAL_STATE("pkauth.illegal_state"),

  /** Ceremony state could not be reconstructed (e.g. challenge expired). */
  CHALLENGE_NOT_FOUND("pkauth.challenge.not_found"),

  /** Asserted credential is not registered to any user. */
  CREDENTIAL_NOT_FOUND("pkauth.credential.not_found"),

  /** A credential with the supplied id is already registered. */
  CREDENTIAL_DUPLICATE("pkauth.credential.duplicate"),

  /** Origin reported by the client is not in the configured allow-list. */
  ORIGIN_MISMATCH("pkauth.origin.mismatch"),

  /** Attestation policy rejected the supplied attestation statement. */
  ATTESTATION_REJECTED("pkauth.attestation.rejected"),

  /** Authenticator signature counter went backwards. */
  COUNTER_REGRESSION("pkauth.counter.regression"),

  /** Ceremony required user verification but the assertion did not provide it. */
  USER_VERIFICATION_REQUIRED("pkauth.uv.required"),

  /** WebAuthn signature failed cryptographic validation. */
  INVALID_SIGNATURE("pkauth.signature.invalid"),

  /** Request payload was malformed or violated WebAuthn structural rules. */
  INVALID_PAYLOAD("pkauth.payload.invalid"),

  /** Rate limit on an operation has been exceeded. */
  RATE_LIMITED("pkauth.rate_limited");

  private final String code;

  PkAuthErrorCode(String code) {
    this.code = code;
  }

  public String code() {
    return code;
  }
}
