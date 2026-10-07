// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.auth;

import com.codeheadsystems.pkauth.jwt.JwtVerificationResult;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import jakarta.inject.Inject;
import java.util.Objects;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Dropwizard {@link Authenticator} that validates a pk-auth JWT and surfaces a {@link
 * PkAuthPasskeyPrincipal}. Brief §6.11 — "Dropwizard → a Jersey {@code Authenticator}".
 *
 * <p>Verification failures (bad signature, expired, wrong issuer/audience) return {@link
 * Optional#empty()}, which causes {@link PkAuthDropwizardAuthFilter} to emit a 401. Malformed
 * payloads are intentionally treated the same: we never leak the underlying reason to the client.
 */
public final class PkAuthDropwizardAuthenticator
    implements Authenticator<PkAuthPasskeyCredentials, PkAuthPasskeyPrincipal> {

  private static final Logger LOG = LoggerFactory.getLogger(PkAuthDropwizardAuthenticator.class);

  private final PkAuthJwtValidator validator;

  @Inject
  public PkAuthDropwizardAuthenticator(PkAuthJwtValidator validator) {
    this.validator = Objects.requireNonNull(validator, "validator");
  }

  @Override
  public Optional<PkAuthPasskeyPrincipal> authenticate(PkAuthPasskeyCredentials credentials)
      throws AuthenticationException {
    JwtVerificationResult result = validator.validate(credentials.token());
    if (result instanceof JwtVerificationResult.Success success) {
      // The JWT's jti is not exposed via JwtClaims (it's a Nimbus-level field), so we use a
      // deterministic-but-opaque placeholder when not surfaced. The validator already enforced
      // signature, issuer, audience, and expiry, so the principal is safe to construct.
      return Optional.of(new PkAuthPasskeyPrincipal(success.claims().userHandle(), "verified"));
    }
    LOG.debug("auth.jwt.rejected reason={}", result.getClass().getSimpleName());
    return Optional.empty();
  }
}
