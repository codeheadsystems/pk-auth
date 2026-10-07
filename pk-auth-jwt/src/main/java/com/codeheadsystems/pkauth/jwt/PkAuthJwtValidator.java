// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * Validates pk-auth JWTs produced by {@link PkAuthJwtIssuer}. Separate from issuance so adapter
 * modules can take this class without pulling in signing keys.
 *
 * <p>No revocation is applied by default. Once issued, a token is considered valid until its {@code
 * exp} claim expires. An application that needs to invalidate tokens early (e.g., on logout-all or
 * user disable) supplies a custom {@link RevocationCheck} via the four-argument constructor. The
 * default behaviour is {@link RevocationCheck#allow()}, which never revokes. A revoked token
 * produces a {@link JwtVerificationResult.Revoked} result rather than {@link
 * JwtVerificationResult.Success}.
 */
public final class PkAuthJwtValidator {

  private final JwtConfig config;
  private final JwtKeyset keyset;
  private final ClockProvider clockProvider;
  private final RevocationCheck revocationCheck;
  private final AccessTokenStore accessTokenStore;
  private final boolean statefulStore;

  /**
   * Constructs a validator with no-op revocation and no-op access-token store (tokens are valid
   * until {@code exp}). Equivalent to {@code new PkAuthJwtValidator(config, keyset, clockProvider,
   * RevocationCheck.allow(), AccessTokenStore.noop())}.
   */
  public PkAuthJwtValidator(JwtConfig config, JwtKeyset keyset, ClockProvider clockProvider) {
    this(config, keyset, clockProvider, RevocationCheck.allow(), AccessTokenStore.noop());
  }

  /**
   * Constructs a validator with a custom {@link RevocationCheck} and the default no-op {@link
   * AccessTokenStore}. This constructor suits lightweight deny-list invalidation without persisting
   * every issued JTI.
   */
  public PkAuthJwtValidator(
      JwtConfig config,
      JwtKeyset keyset,
      ClockProvider clockProvider,
      RevocationCheck revocationCheck) {
    this(config, keyset, clockProvider, revocationCheck, AccessTokenStore.noop());
  }

  /**
   * Constructs a validator with both a custom {@link RevocationCheck} and a custom {@link
   * AccessTokenStore}. The store is consulted on every {@link #validate(String)} call after
   * signature and standard-claim checks; an absent jti yields {@link
   * JwtVerificationResult.Revoked}. The matching {@link PkAuthJwtIssuer} must be wired with the
   * same store so issued JTIs are recorded.
   *
   * @since 1.1.0
   */
  public PkAuthJwtValidator(
      JwtConfig config,
      JwtKeyset keyset,
      ClockProvider clockProvider,
      RevocationCheck revocationCheck,
      AccessTokenStore accessTokenStore) {
    this.config = Objects.requireNonNull(config, "config");
    this.keyset = Objects.requireNonNull(keyset, "keyset");
    this.clockProvider = Objects.requireNonNull(clockProvider, "clockProvider");
    this.revocationCheck = Objects.requireNonNull(revocationCheck, "revocationCheck");
    this.accessTokenStore = Objects.requireNonNull(accessTokenStore, "accessTokenStore");
    this.statefulStore = accessTokenStore != NoopAccessTokenStore.INSTANCE;
  }

  /** Verifies signature and standard claims, then reconstructs a {@link JwtClaims}. */
  public JwtVerificationResult validate(String token) {
    Objects.requireNonNull(token, "token");
    SignedJWT jwt;
    try {
      jwt = SignedJWT.parse(token);
    } catch (ParseException e) {
      return new JwtVerificationResult.Malformed("unparseable: " + e.getMessage());
    }

    JWSAlgorithm alg = jwt.getHeader().getAlgorithm();
    if (alg == null || !alg.equals(keyset.algorithm())) {
      return new JwtVerificationResult.InvalidSignature();
    }

    String kid = jwt.getHeader().getKeyID();
    if (!verifyAgainstCandidateKeys(jwt, kid)) {
      return new JwtVerificationResult.InvalidSignature();
    }

    JWTClaimsSet body;
    try {
      body = jwt.getJWTClaimsSet();
    } catch (ParseException e) {
      return new JwtVerificationResult.Malformed("invalid claims set: " + e.getMessage());
    }

    if (!config.issuer().equals(body.getIssuer())) {
      return new JwtVerificationResult.WrongIssuer(
          config.issuer(), body.getIssuer() == null ? "" : body.getIssuer());
    }

    List<String> aud = body.getAudience();
    Set<String> allowed = config.allowedAudiences();
    String matchedAudience = null;
    if (aud != null) {
      for (String a : aud) {
        if (allowed.contains(a)) {
          matchedAudience = a;
          break;
        }
      }
    }
    if (matchedAudience == null) {
      return new JwtVerificationResult.WrongAudience(
          String.join(",", allowed), aud == null ? "" : String.join(",", aud));
    }

    Instant now = clockProvider.now();
    Date exp = body.getExpirationTime();
    if (exp == null) {
      return new JwtVerificationResult.MissingClaim("exp");
    }
    if (now.isAfter(exp.toInstant().plus(config.clockSkew()))) {
      return new JwtVerificationResult.Expired(exp.toInstant());
    }

    Date nbf = body.getNotBeforeTime();
    if (nbf != null && now.isBefore(nbf.toInstant().minus(config.clockSkew()))) {
      return new JwtVerificationResult.NotYetValid(nbf.toInstant());
    }

    String subject = body.getSubject();
    if (subject == null || subject.isEmpty()) {
      return new JwtVerificationResult.MissingClaim("sub");
    }
    UserHandle userHandle;
    try {
      userHandle = UserHandle.of(Base64Url.decode(subject));
    } catch (RuntimeException e) {
      return new JwtVerificationResult.Malformed("invalid sub: " + e.getMessage());
    }

    String jti = body.getJWTID();
    if (revocationCheck.isRevoked(jti, subject)) {
      return new JwtVerificationResult.Revoked(jti, subject);
    }
    if (statefulStore) {
      // Stateful mode: every token we issue carries a jti recorded in the store. A token without a
      // jti can't be checked against the store, so it can't be proven un-revoked — reject it rather
      // than letting it bypass the revocation gate entirely. (The noop store leaves statefulStore
      // false, so stateless deployments skip this branch and remain valid-until-exp.)
      if (jti == null) {
        return new JwtVerificationResult.MissingClaim("jti");
      }
      if (!accessTokenStore.exists(jti)) {
        // jti not in the store: logout / admin-revoke / never recorded.
        return new JwtVerificationResult.Revoked(jti, subject);
      }
    }

    String methodClaim = stringClaim(body, PkAuthJwtIssuer.CLAIM_METHOD);
    if (methodClaim == null) {
      return new JwtVerificationResult.MissingClaim(PkAuthJwtIssuer.CLAIM_METHOD);
    }
    AuthMethod method;
    try {
      method = AuthMethod.fromWireValue(methodClaim);
    } catch (IllegalArgumentException e) {
      return new JwtVerificationResult.Malformed("unknown pkauth.method: " + methodClaim);
    }

    byte @Nullable [] credentialId = null;
    String credClaim = stringClaim(body, PkAuthJwtIssuer.CLAIM_CRED);
    if (method == AuthMethod.PASSKEY) {
      if (credClaim == null) {
        return new JwtVerificationResult.MissingClaim(PkAuthJwtIssuer.CLAIM_CRED);
      }
      try {
        credentialId = Base64Url.decode(credClaim);
      } catch (RuntimeException e) {
        return new JwtVerificationResult.Malformed("invalid pkauth.cred: " + e.getMessage());
      }
    } else if (credClaim != null) {
      return new JwtVerificationResult.Malformed(
          "pkauth.cred must not appear when pkauth.method != passkey");
    }

    List<String> amr = stringListClaim(body, PkAuthJwtIssuer.CLAIM_AMR);
    if (amr == null) {
      amr = List.of();
    }

    Map<String, Object> remaining = removeKnownClaims(body.toJSONObject());
    return new JwtVerificationResult.Success(
        new JwtClaims(
            userHandle,
            method,
            credentialId,
            amr,
            remaining.isEmpty() ? null : remaining,
            matchedAudience));
  }

  /**
   * Verifies the JWT signature against candidate keys from the keyset.
   *
   * <p>When the token header carries a {@code kid} and at least one key in the keyset also has a
   * {@code kid} assigned, only the key(s) whose {@code kid} matches the header value are tried.
   * This prevents a forged token claiming {@code kid=X} from being accepted by a different key Y,
   * which is the security property enforced.
   *
   * <p>If the keyset contains at least one key with an assigned {@code kid} but the token header
   * carries no {@code kid}, the token is rejected. Without this rule a leaked retired key (still
   * present in the keyset for rotation) could sign a kid-less token and be silently accepted,
   * defeating kid-based rotation.
   *
   * <p>If the keyset contains no keys with an assigned {@code kid} (fully legacy keyset, e.g. HS256
   * built without explicit key IDs), the {@code kid} filter is skipped entirely and all keys are
   * tried so that legacy single-key deployments continue to work without modification.
   */
  private boolean verifyAgainstCandidateKeys(SignedJWT jwt, @Nullable String kid) {
    // Fetch the full set of verification keys (no filter yet).
    JWKSelector allSelector = new JWKSelector(new JWKMatcher.Builder().build());
    List<JWK> allCandidates;
    try {
      allCandidates = keyset.verificationSource().get(allSelector, (SecurityContext) null);
    } catch (com.nimbusds.jose.KeySourceException | RuntimeException e) {
      return false;
    }

    boolean keysetHasKid = allCandidates.stream().anyMatch(k -> k.getKeyID() != null);

    List<JWK> candidates;
    if (kid != null) {
      if (keysetHasKid) {
        // The keyset has kid-bearing keys, so kid-based filtering is meaningful.
        // Only try the key(s) whose kid matches the header — do NOT fall back to other keys.
        JWKSelector kidSelector = new JWKSelector(new JWKMatcher.Builder().keyID(kid).build());
        try {
          candidates = keyset.verificationSource().get(kidSelector, (SecurityContext) null);
        } catch (com.nimbusds.jose.KeySourceException | RuntimeException e) {
          return false;
        }
        if (candidates.isEmpty()) {
          // kid was specified, keyset has kid-bearing keys, but none matched — reject.
          return false;
        }
      } else {
        // Token carries a kid but the keyset is fully kid-less — no filtering possible, try all.
        candidates = allCandidates;
      }
    } else {
      // No kid in header.
      if (keysetHasKid) {
        // At least one key in the keyset carries a kid. Requiring kid in the header prevents a
        // leaked retired key from signing a kid-less token that the validator would otherwise
        // accept by trying every key, defeating kid-based rotation.
        return false;
      }
      // Fully legacy keyset (no key has a kid): backwards-compatible try-all path.
      candidates = allCandidates;
    }

    for (JWK candidate : candidates) {
      JWSVerifier verifier;
      try {
        if (candidate instanceof OctetSequenceKey oct) {
          verifier = new MACVerifier(oct);
        } else if (candidate instanceof ECKey ec) {
          verifier = new ECDSAVerifier(ec);
        } else {
          continue;
        }
        if (jwt.verify(verifier)) {
          return true;
        }
      } catch (JOSEException e) {
        // try next key
      }
    }
    return false;
  }

  private static @Nullable String stringClaim(JWTClaimsSet body, String name) {
    try {
      return body.getStringClaim(name);
    } catch (ParseException e) {
      return null;
    }
  }

  private static @Nullable List<String> stringListClaim(JWTClaimsSet body, String name) {
    try {
      return body.getStringListClaim(name);
    } catch (ParseException e) {
      return null;
    }
  }

  private static Map<String, Object> removeKnownClaims(Map<String, Object> raw) {
    Map<String, Object> copy = new LinkedHashMap<>(raw);
    copy.remove("iss");
    copy.remove("sub");
    copy.remove("aud");
    copy.remove("iat");
    copy.remove("nbf");
    copy.remove("exp");
    copy.remove("jti");
    copy.remove(PkAuthJwtIssuer.CLAIM_METHOD);
    copy.remove(PkAuthJwtIssuer.CLAIM_CRED);
    copy.remove(PkAuthJwtIssuer.CLAIM_AMR);
    return copy;
  }
}
