// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import java.time.Instant;
import java.util.Objects;

/**
 * Closed sum of outcomes from {@link PkAuthJwtValidator#validate(String)}.
 *
 * @since 1.1.0
 */
public sealed interface JwtVerificationResult {

  /** Token signature verified and all standard claims pass. */
  record Success(JwtClaims claims) implements JwtVerificationResult {
    public Success {
      Objects.requireNonNull(claims, "claims");
    }
  }

  /** Signature verification failed against every key in the keyset. */
  record InvalidSignature() implements JwtVerificationResult {}

  /** Token is past its {@code exp} claim (after applying the configured clock skew). */
  record Expired(Instant exp) implements JwtVerificationResult {
    public Expired {
      Objects.requireNonNull(exp, "exp");
    }
  }

  /** Token's {@code nbf} is still in the future (after applying the configured clock skew). */
  record NotYetValid(Instant nbf) implements JwtVerificationResult {
    public NotYetValid {
      Objects.requireNonNull(nbf, "nbf");
    }
  }

  /** {@code iss} claim does not match the configured issuer. */
  record WrongIssuer(String expected, String actual) implements JwtVerificationResult {
    public WrongIssuer {
      Objects.requireNonNull(expected, "expected");
      Objects.requireNonNull(actual, "actual");
    }
  }

  /** {@code aud} claim does not match the configured audience. */
  record WrongAudience(String expected, String actual) implements JwtVerificationResult {
    public WrongAudience {
      Objects.requireNonNull(expected, "expected");
      Objects.requireNonNull(actual, "actual");
    }
  }

  /** Token does not parse as a valid JWS. */
  record Malformed(String detail) implements JwtVerificationResult {
    public Malformed {
      Objects.requireNonNull(detail, "detail");
    }
  }

  /** A required pk-auth claim is missing from the payload. */
  record MissingClaim(String name) implements JwtVerificationResult {
    public MissingClaim {
      Objects.requireNonNull(name, "name");
    }
  }

  /**
   * Token has been explicitly revoked by the configured {@link RevocationCheck}. This occurs when
   * the token's {@code jti} or {@code sub} appears in the application's revocation store.
   */
  record Revoked(String jti, String subject) implements JwtVerificationResult {
    public Revoked {
      Objects.requireNonNull(subject, "subject");
    }
  }
}
