// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

/**
 * SPI hook for token revocation. Adopters who need revocation (e.g., logout-all, disable-user)
 * should provide an implementation backed by their datastore. Default implementation is a no-op so
 * the library remains stateless by default.
 *
 * <p>Register a custom implementation by passing it to the {@link
 * PkAuthJwtValidator#PkAuthJwtValidator(JwtConfig, JwtKeyset,
 * com.codeheadsystems.pkauth.spi.ClockProvider, RevocationCheck)} constructor.
 *
 * @since 1.1.0
 */
@FunctionalInterface
public interface RevocationCheck {

  /**
   * Return {@code true} if the token (identified by its {@code jti} / {@code sub}) has been revoked
   * and must be rejected.
   *
   * <p><strong>Handle a {@code null} jti.</strong> A token may carry no {@code jti}, in which case
   * {@code jti} is {@code null} here. An implementation that maintains a deny-list keyed solely on
   * {@code jti} must decide explicitly what to do with a jti-less token — typically reject it (the
   * deny-list can never prove it un-revoked) or fall back to a {@code sub}-scoped rule. A naive
   * {@code denyList.contains(jti)} silently lets every jti-less token through. (In stateful mode,
   * {@link PkAuthJwtValidator} already rejects jti-less tokens before this check via the {@link
   * AccessTokenStore}; this guidance matters for stateless deployments that rely only on a {@code
   * RevocationCheck}.)
   *
   * @param jti the JWT ID claim ({@code jti}), may be {@code null} if absent from the token
   * @param subject the subject claim ({@code sub}), always non-null when called from the validator
   * @return {@code true} to reject the token; {@code false} to allow it
   * @since 1.1.0
   */
  boolean isRevoked(String jti, String subject);

  /**
   * Returns a no-op {@link RevocationCheck} that always allows tokens (never revokes). This is the
   * default behaviour when no custom implementation is supplied.
   */
  static RevocationCheck allow() {
    return (jti, sub) -> false;
  }
}
