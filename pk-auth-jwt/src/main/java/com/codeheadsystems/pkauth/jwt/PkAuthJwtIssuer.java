// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.jspecify.annotations.Nullable;

/**
 * Issues pk-auth JWTs. Maps {@link JwtClaims} onto the standard {@code iss/sub/aud/iat/nbf/exp/jti}
 * claims plus {@code pkauth.method}, {@code pkauth.cred}, {@code pkauth.amr}.
 *
 * <p>If a non-noop {@link AccessTokenStore} is bound, each issued token's jti is persisted in the
 * store before {@link #issue(JwtClaims)} returns. A store failure propagates — partial state
 * (signed token returned but unrecorded) is intentionally not tolerated.
 */
public final class PkAuthJwtIssuer {

  /** Header value for the pk-auth method claim. */
  public static final String CLAIM_METHOD = "pkauth.method";

  /**
   * Header value for the pk-auth credential id claim (base64url string, present only for passkeys).
   */
  public static final String CLAIM_CRED = "pkauth.cred";

  /** Header value for the pk-auth authentication method reference array. */
  public static final String CLAIM_AMR = "pkauth.amr";

  private final JwtConfig config;
  private final JwtKeyset keyset;
  private final ClockProvider clockProvider;
  private final AccessTokenStore accessTokenStore;

  /**
   * Constructs an issuer with a no-op access-token store (stateless mode). Equivalent to {@code new
   * PkAuthJwtIssuer(config, keyset, clockProvider, AccessTokenStore.noop())}.
   */
  public PkAuthJwtIssuer(JwtConfig config, JwtKeyset keyset, ClockProvider clockProvider) {
    this(config, keyset, clockProvider, AccessTokenStore.noop());
  }

  /**
   * Constructs an issuer that records each issued JTI through the supplied {@link
   * AccessTokenStore}. Use this constructor when the host needs server-side revocation of access
   * tokens; pair with a {@link PkAuthJwtValidator} configured with the same store so {@link
   * AccessTokenStore#exists(String)} is consulted at validation time.
   *
   * @since 1.1.0
   */
  public PkAuthJwtIssuer(
      JwtConfig config,
      JwtKeyset keyset,
      ClockProvider clockProvider,
      AccessTokenStore accessTokenStore) {
    this.config = Objects.requireNonNull(config, "config");
    this.keyset = Objects.requireNonNull(keyset, "keyset");
    this.clockProvider = Objects.requireNonNull(clockProvider, "clockProvider");
    this.accessTokenStore = Objects.requireNonNull(accessTokenStore, "accessTokenStore");
  }

  /**
   * Issues a signed JWT for the supplied claims. The {@code aud} claim is taken from {@link
   * JwtClaims#audience()} when set, falling back to {@link JwtConfig#defaultAudience()}; the
   * access-token TTL is then looked up via {@link JwtConfig#ttlPolicy()} keyed by that audience.
   *
   * <p>The issued jti is recorded in the configured {@link AccessTokenStore} <em>before</em> the
   * wire token is returned. If recording fails, the exception propagates and no token is surfaced
   * to the caller — the host must retry or surface the failure upstream.
   */
  public String issue(JwtClaims claims) {
    return issue(claims, null);
  }

  /**
   * Issues a signed JWT whose lifetime is {@code ttlOverride} instead of the per-audience
   * access-token TTL resolved from {@link JwtConfig#ttlPolicy()}. Use this for short-lived,
   * single-purpose tokens (e.g. magic links) that must NOT inherit the full access-token validity
   * window — a magic link minted at the 1-hour access TTL stays redeemable as a bearer token (and
   * replayable past its single-use JTI retention) far longer than intended. A {@code null} {@code
   * ttlOverride} falls back to the audience's access TTL, making this exactly equivalent to {@link
   * #issue(JwtClaims)}.
   *
   * @param claims the claims to sign
   * @param ttlOverride the token lifetime, or {@code null} to use the audience access TTL
   * @return the serialized, signed JWT
   * @since 2.2.0
   */
  public String issue(JwtClaims claims, @Nullable Duration ttlOverride) {
    Objects.requireNonNull(claims, "claims");
    Instant now = clockProvider.now();
    Instant nbf = now.minus(config.notBeforeSkew());
    String audience = claims.audience() != null ? claims.audience() : config.defaultAudience();
    Instant exp =
        now.plus(ttlOverride != null ? ttlOverride : config.ttlPolicy().accessTtl(audience));
    String jti = UUID.randomUUID().toString();

    JWTClaimsSet.Builder body =
        new JWTClaimsSet.Builder()
            .issuer(config.issuer())
            .audience(audience)
            .subject(Base64Url.encode(claims.userHandle().value()))
            .issueTime(Date.from(now))
            .notBeforeTime(Date.from(nbf))
            .expirationTime(Date.from(exp))
            .jwtID(jti)
            .claim(CLAIM_METHOD, claims.method().wireValue())
            .claim(CLAIM_AMR, List.copyOf(claims.amr()));

    byte[] credId = claims.credentialId();
    if (credId != null) {
      body.claim(CLAIM_CRED, Base64Url.encode(credId));
    }

    if (claims.additionalClaims() != null) {
      for (Map.Entry<String, Object> e : claims.additionalClaims().entrySet()) {
        body.claim(e.getKey(), e.getValue());
      }
    }

    JWSHeader header =
        new JWSHeader.Builder(keyset.algorithm()).keyID(keyset.currentKeyId()).build();
    SignedJWT jwt = new SignedJWT(header, body.build());
    try {
      jwt.sign(keyset.signer());
    } catch (JOSEException e) {
      throw new IllegalStateException("Failed to sign JWT", e);
    }

    // Persist BEFORE returning — a recorded-after-return order would let a malicious caller use the
    // token before the store knew about it (the validator would call exists() and see false). For
    // the noop store this is free; for a real store the call must succeed or issuance fails.
    accessTokenStore.record(jti, claims.userHandle(), audience, Optional.empty(), now, exp);

    return jwt.serialize();
  }
}
