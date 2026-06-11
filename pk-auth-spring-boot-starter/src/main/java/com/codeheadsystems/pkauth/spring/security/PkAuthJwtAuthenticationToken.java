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
 * <p>This is intentionally permissive — the filter sets it once the JWT signature and standard
 * claims (iss / aud / exp) have been validated by {@link com.codeheadsystems.pkauth.jwt
 * .PkAuthJwtValidator}.
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
   * once {@link #eraseCredentials()} has been invoked by Spring Security's {@code ProviderManager}
   * — applications that need the raw bearer for outbound calls must capture it before the security
   * context post-processing pass.
   */
  public @Nullable String getToken() {
    return token;
  }

  /**
   * Drops the raw bearer string so it no longer lives on the {@code SecurityContext} for the
   * lifetime of the request. Spring Security calls this after authentication when {@code
   * eraseCredentials} is enabled (default) on the {@code AuthenticationManager}; for the pk-auth
   * filter chain we additionally invoke it explicitly so the in-memory copy of the JWT shrinks to
   * just the parsed {@link JwtClaims} view.
   *
   * @since 0.9.1
   */
  @Override
  public void eraseCredentials() {
    super.eraseCredentials();
    this.token = null;
  }
}
