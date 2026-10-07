// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import com.codeheadsystems.pkauth.api.AssertionResult;
import java.util.List;
import java.util.Objects;

/**
 * Shared JWT-minting helper used by every adapter (Spring, Dropwizard, Micronaut) immediately after
 * a successful WebAuthn assertion. This helper standardises the claim shape so a token minted by
 * the Spring adapter is byte-equivalent (modulo {@code jti}/{@code iat}) to one minted by
 * Dropwizard or Micronaut.
 *
 * <p>Standardised {@code amr}: {@link #ASSERTION_AMR} is {@code ["pkauth", "webauthn"]}. The RFC
 * 8176 registry does not define a passkey-specific token, so the claim uses the descriptive {@code
 * "pkauth"} (the library tag) plus the standard {@code "webauthn"} that consumers can recognise.
 *
 * <p>This helper takes no {@code CredentialRepository}; the credential label is the adapter's
 * concern (it appears in the HTTP response body, not the JWT), so the adapter looks it up once when
 * it needs it, not through this helper.
 */
public final class PkAuthCeremonyJwt {

  /** Authentication method reference array embedded in every passkey-issued JWT. */
  public static final List<String> ASSERTION_AMR = List.of("pkauth", "webauthn");

  private PkAuthCeremonyJwt() {}

  /**
   * Mints a JWT for a successful WebAuthn assertion. The subject, credential id, and amr list are
   * derived from {@code success}; the issuer/audience/ttl come from the {@link PkAuthJwtIssuer}'s
   * configured {@link JwtConfig}.
   *
   * @param success the successful assertion outcome from the ceremony service.
   * @param issuer the configured JWT issuer.
   * @return a signed pk-auth JWT.
   */
  public static String mintForAssertion(AssertionResult.Success success, PkAuthJwtIssuer issuer) {
    Objects.requireNonNull(success, "success");
    Objects.requireNonNull(issuer, "issuer");
    JwtClaims claims =
        JwtClaims.forPasskey(success.userHandle(), success.credentialId().value(), ASSERTION_AMR);
    return issuer.issue(claims);
  }
}
