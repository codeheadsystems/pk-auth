// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.auth;

import io.dropwizard.auth.AuthFilter;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.container.ContainerRequestContext;
import java.io.IOException;
import java.util.Objects;
import java.util.Optional;
import org.jspecify.annotations.Nullable;

/**
 * Bearer-token {@link io.dropwizard.auth.AuthFilter} that extracts a JWT from the {@code
 * Authorization: Bearer ...} header and delegates verification to a {@link
 * PkAuthDropwizardAuthenticator}. Brief §6.11: "JWT validation via a Jersey filter".
 *
 * <p>This filter is hand-rolled instead of using Dropwizard's bundled {@code
 * OAuthCredentialAuthFilter}, so that the wire-credential type is {@link PkAuthPasskeyCredentials}
 * (strongly typed in the bundle's DI graph) rather than {@code String}.
 */
@Priority(Priorities.AUTHENTICATION)
public final class PkAuthDropwizardAuthFilter
    extends AuthFilter<PkAuthPasskeyCredentials, PkAuthPasskeyPrincipal> {

  private static final String BEARER_PREFIX = "Bearer ";

  /** Builder honouring the standard {@link AuthFilter.AuthFilterBuilder} contract. */
  public static final class Builder
      extends AuthFilterBuilder<
          PkAuthPasskeyCredentials, PkAuthPasskeyPrincipal, PkAuthDropwizardAuthFilter> {
    @Override
    protected PkAuthDropwizardAuthFilter newInstance() {
      return new PkAuthDropwizardAuthFilter();
    }
  }

  private PkAuthDropwizardAuthFilter() {}

  @Override
  public void filter(ContainerRequestContext requestContext) throws IOException {
    String header = requestContext.getHeaderString("Authorization");
    Optional<PkAuthPasskeyCredentials> credentials = parseBearer(header);
    boolean authenticated =
        credentials.isPresent() && authenticate(requestContext, credentials.get(), "Bearer");
    if (!authenticated) {
      throw new WebApplicationException(unauthorizedHandler.buildResponse(prefix, realm));
    }
  }

  private static Optional<PkAuthPasskeyCredentials> parseBearer(@Nullable String header) {
    if (header == null || !header.startsWith(BEARER_PREFIX)) {
      return Optional.empty();
    }
    String token = header.substring(BEARER_PREFIX.length()).trim();
    if (token.isEmpty()) {
      return Optional.empty();
    }
    return Optional.of(new PkAuthPasskeyCredentials(token));
  }

  /** Convenience: produces a fully wired filter from an authenticator. */
  public static PkAuthDropwizardAuthFilter build(PkAuthDropwizardAuthenticator authenticator) {
    Objects.requireNonNull(authenticator, "authenticator");
    Builder b = new Builder();
    b.setAuthenticator(authenticator);
    b.setPrefix("Bearer");
    b.setRealm("pk-auth");
    return b.buildAuthFilter();
  }
}
