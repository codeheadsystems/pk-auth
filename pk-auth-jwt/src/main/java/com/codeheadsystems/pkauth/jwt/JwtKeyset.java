// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Holds the active signing key and the full set of verification keys. The newest key signs new
 * tokens; older keys remain in the set so previously-issued tokens still verify (brief §6.2 "key
 * rotation: support a JWKSource with multiple active keys, the newest signs").
 */
public final class JwtKeyset {

  private final JWK signingKey;
  private final JWSAlgorithm algorithm;
  private final JWKSource<SecurityContext> verificationSource;

  private JwtKeyset(JWK signingKey, JWSAlgorithm algorithm, List<JWK> verificationKeys) {
    this.signingKey = signingKey;
    this.algorithm = algorithm;
    this.verificationSource = new ImmutableJWKSet<>(new JWKSet(verificationKeys));
  }

  /**
   * HS256 (symmetric) keyset. Appropriate whenever the issuer and verifier share a trust boundary
   * (the common single-issuer/single-verifier deployment) — not a "dev-only" mode. The supplied
   * secret must be at least 256 bits per RFC 7518 §3.2; Nimbus rejects shorter keys. With a {@code
   * >= 256}-bit key HMAC-SHA256 is also the quantum-conservative choice (Shor does not apply;
   * Grover leaves ~128-bit effective security). Use {@link #es256(ECKey, ECKey...)} instead only
   * when an untrusted third party must verify tokens without the power to mint them. See the
   * package Javadoc and {@code docs/threat-model.md} (Post-quantum readiness).
   */
  public static JwtKeyset hs256(byte[] secret) {
    Objects.requireNonNull(secret, "secret");
    if (secret.length < 32) {
      throw new IllegalArgumentException(
          "HS256 secret must be at least 256 bits (32 bytes) per RFC 7518 §3.2; got "
              + secret.length
              + " bytes");
    }
    OctetSequenceKey key =
        new OctetSequenceKey.Builder(secret).algorithm(JWSAlgorithm.HS256).build();
    return new JwtKeyset(key, JWSAlgorithm.HS256, List.of(key));
  }

  /**
   * ES256 keyset. {@code current} is the active signing key; tokens it issues are signed by it.
   * Each entry in {@code retired} remains valid for verification — typical pattern for graceful key
   * rotation.
   */
  public static JwtKeyset es256(ECKey current, ECKey... retired) {
    Objects.requireNonNull(current, "current");
    List<JWK> all = new ArrayList<>();
    // Store ONLY public halves in the verification set. verificationSource() is public and a host
    // may publish it as a JWKS endpoint; including the private `d` parameter here would leak the
    // signing key. The full `current` (with the private key) is retained separately for signer().
    all.add(current.toPublicJWK());
    for (ECKey r : retired) {
      Objects.requireNonNull(r, "retired key");
      all.add(r.toPublicJWK());
    }
    return new JwtKeyset(current, JWSAlgorithm.ES256, all);
  }

  /** Returns a {@link JWSSigner} for the current signing key. */
  public JWSSigner signer() {
    try {
      if (signingKey instanceof OctetSequenceKey oct) {
        return new MACSigner(oct);
      }
      if (signingKey instanceof ECKey ec) {
        return new ECDSASigner(ec);
      }
    } catch (JOSEException e) {
      throw new IllegalStateException("Unable to build JWS signer", e);
    }
    throw new IllegalStateException(
        "Unsupported signing key type: " + signingKey.getClass().getName());
  }

  /** Identifier of the current signing key used as the JWT header {@code kid}, if available. */
  public String currentKeyId() {
    return signingKey.getKeyID() == null ? "current" : signingKey.getKeyID();
  }

  /** Algorithm of the current signing key. */
  public JWSAlgorithm algorithm() {
    return algorithm;
  }

  /** Source of public verification keys (the current key plus any retired ones). */
  public JWKSource<SecurityContext> verificationSource() {
    return verificationSource;
  }
}
