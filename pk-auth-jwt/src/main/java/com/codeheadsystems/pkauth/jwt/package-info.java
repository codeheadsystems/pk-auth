// SPDX-License-Identifier: MIT

/**
 * JWT issuance and validation for pk-auth-issued tokens.
 *
 * <p>The choice between HS256 and ES256 depends on trust topology, not on a
 * development-versus-production distinction. Both are production-grade; the deciding factor is who
 * needs to verify the token:
 *
 * <ul>
 *   <li>HS256 (symmetric): the issuer and verifier share one secret. This is the right default when
 *       pk-auth both mints and validates the token (the common single-issuer/single-verifier
 *       deployment). It is also the quantum-conservative choice: HMAC-SHA256 is not broken by
 *       Shor's algorithm, and with a {@code >= 256}-bit key (enforced by {@link
 *       com.codeheadsystems.pkauth.jwt.JwtKeyset#hs256(byte[])}) Grover's algorithm leaves roughly
 *       128-bit effective security. Its limitation is trust, not cryptography: anyone who can
 *       verify can also forge, so the secret must never leave the trust boundary.
 *   <li>ES256 (asymmetric): exists for untrusted third-party verification. Publishing the public
 *       key lets external services validate tokens without the power to mint them. That capability
 *       costs post-quantum exposure: ES256 is an elliptic-curve signature and is Shor-vulnerable.
 *       The exposure is bounded by the (short) token TTL: a forged signature is only useful within
 *       the lifetime of a token, and a CRQC does not yet exist.
 * </ul>
 *
 * <p>See {@code docs/threat-model.md} (Post-quantum readiness) and ADR 0019.
 */
@org.jspecify.annotations.NullMarked
package com.codeheadsystems.pkauth.jwt;
