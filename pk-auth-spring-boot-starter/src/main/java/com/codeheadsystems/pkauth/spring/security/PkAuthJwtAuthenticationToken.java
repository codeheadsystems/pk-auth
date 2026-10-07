// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.security;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.jwt.JwtClaims;
import java.util.List;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Spring Security {@code Authentication} for a pk-auth-issued JWT. The principal is the verified
 * {@link UserHandle}; the underlying {@link JwtClaims} is available via {@link #getClaims()} for
 * downstream controllers that want to inspect the authentication method or credential id.
 *
 * <p>This token is permissive: the filter sets it once the JWT signature and standard claims (iss /
 * aud / exp) have been validated by {@link com.codeheadsystems.pkauth.jwt .PkAuthJwtValidator}.
 */
public final class PkAuthJwtAuthenticationToken extends AbstractAuthenticationToken {

  private static final long serialVersionUID = 1L;

  private final UserHandle principal;
  private final JwtClaims claims;
  private @Nullable String token;

  public PkAuthJwtAuthenticationToken(UserHandle principal, JwtClaims claims, String token) {
    super(authorities(claims));
    this.principal = principal;
    this.claims = claims;
    this.token = token;
    setAuthenticated(true);
  }

  private static List<GrantedAuthority> authorities(JwtClaims claims) {
    return List.of(
        new SimpleGrantedAuthority("ROLE_USER"),
        new SimpleGrantedAuthority("PKAUTH_METHOD_" + claims.method().name()));
  }

  @Override
  public @Nullable Object getCredentials() {
    return token;
  }

  @Override
  public UserHandle getPrincipal() {
    return principal;
  }

  /** The validated pk-auth claim set. */
  public JwtClaims getClaims() {
    return claims;
  }

  /**
   * Raw token string (useful for downstream services that want to forward it). Returns {@code null}
   * once {@link #eraseCredentials()} has been called. The shipped {@link
   * PkAuthJwtAuthenticationFilter} bypasses the {@code AuthenticationManager} and never calls it,
   * so under the default wiring the token stays available for the whole request.
   */
  public @Nullable String getToken() {
    return token;
  }

  /**
   * Drops the raw bearer string so only the parsed {@link JwtClaims} view remains on the {@code
   * SecurityContext}. Spring Security's {@code ProviderManager} calls this after authentication
   * when {@code eraseCredentials} is enabled (the default), which applies only if a host routes
   * this token through an {@code AuthenticationManager}. The shipped {@link
   * PkAuthJwtAuthenticationFilter} sets the token on the context directly and does not call this
   * method.
   *
   * @since 0.9.1
   */
  @Override
  public void eraseCredentials() {
    super.eraseCredentials();
    this.token = null;
  }
}
