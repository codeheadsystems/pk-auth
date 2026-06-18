// SPDX-License-Identifier: MIT

/**
 * JWT issuance and validation for pk-auth-issued tokens.
 *
 * <p><strong>HS256 vs ES256 is a trust-topology choice, not a dev-vs-prod one.</strong> The older
 * "HS256 for dev, ES256 for production" framing was misleading. Both are production-grade; pick by
 * who needs to verify the token:
 *
 * <ul>
 *   <li><strong>HS256 (symmetric)</strong> — the issuer and verifier share one secret. This is the
 *       right default when pk-auth both mints and validates the token (the common
 *       single-issuer/single-verifier deployment). It is also the <em>quantum-conservative</em>
 *       choice: HMAC-SHA256 is not broken by Shor's algorithm, and with a {@code >= 256}-bit key
 *       (enforced by {@link com.codeheadsystems.pkauth.jwt.JwtKeyset#hs256(byte[])}) Grover's
 *       algorithm leaves roughly 128-bit effective security — comfortably safe. Its limitation is
 *       trust, not cryptography: anyone who can verify can also forge, so the secret must never
 *       leave the trust boundary.
 *   <li><strong>ES256 (asymmetric)</strong> — exists for <em>untrusted third-party
 *       verification</em>: publish the public key so external services validate tokens without the
 *       power to mint them. That capability costs post-quantum exposure — ES256 is an
 *       elliptic-curve signature and is Shor-vulnerable. The exposure is bounded by the (short)
 *       token TTL: a forged signature is only useful within the lifetime of a token, and a CRQC
 *       does not yet exist.
 * </ul>
 *
 * <p>Neither default nor signing behavior is changed by this note; see {@code docs/threat-model.md}
 * (Post-quantum readiness) and ADR 0019.
 */
@org.jspecify.annotations.NullMarked
package com.codeheadsystems.pkauth.jwt;
