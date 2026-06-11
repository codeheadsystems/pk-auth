// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.jwt.JwtVerificationResult;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Filter;
import io.micronaut.http.filter.HttpServerFilter;
import io.micronaut.http.filter.ServerFilterChain;
import org.jspecify.annotations.Nullable;
import org.reactivestreams.Publisher;

/**
 * Validates the JWT on {@code Authorization: Bearer …} headers (when present) and stashes the
 * authenticated {@link UserHandle} on the request as the attribute {@value #ATTR_USER_HANDLE}.
 * Missing / malformed tokens are NOT rejected here — admin controller methods enforce
 * "authenticated user required" themselves. This keeps the filter pluggable and avoids Micronaut
 * Security's generic-heavy SecurityRule surface.
 *
 * <p><b>Threading.</b> Token validation itself is non-blocking (HS256 or RS256 verification only),
 * so the filter does NOT dispatch to a blocking executor and is safe to run on the Netty event
 * loop. The pk-auth SPI is blocking, but the SPI is invoked downstream from the {@code @Controller}
 * — see {@link PkAuthCeremonyController} / {@link PkAuthAdminController}, which both carry
 * {@code @ExecuteOn(TaskExecutors.BLOCKING)}.
 */
@Filter("/auth/admin/**")
public class PkAuthJwtAuthenticationFilter implements HttpServerFilter {

  /** Request attribute key for the authenticated user handle. */
  public static final String ATTR_USER_HANDLE = "pkauth.userHandle";

  private final PkAuthJwtValidator validator;

  public PkAuthJwtAuthenticationFilter(PkAuthJwtValidator validator) {
    this.validator = validator;
  }

  @Override
  public Publisher<io.micronaut.http.MutableHttpResponse<?>> doFilter(
      HttpRequest<?> request, ServerFilterChain chain) {
    String header = request.getHeaders().get("Authorization");
    if (header != null && header.startsWith("Bearer ")) {
      String token = header.substring("Bearer ".length()).trim();
      JwtVerificationResult result = validator.validate(token);
      if (result instanceof JwtVerificationResult.Success success) {
        UserHandle uh = success.claims().userHandle();
        // Use the request's attributes map directly — Micronaut wraps incoming requests in a
        // type that exposes attributes but is not always a MutableHttpRequest instance.
        request.getAttributes().put(ATTR_USER_HANDLE, uh);
      }
    }
    return chain.proceed(request);
  }

  /** Extracts the authenticated user handle from a request, or null if none was attached. */
  public static @Nullable UserHandle attachedUserHandle(HttpRequest<?> request) {
    return request.getAttribute(ATTR_USER_HANDLE, UserHandle.class).orElse(null);
  }

  /** Decodes a base64url-encoded user handle from the path, helper for tests / clients. */
  public static UserHandle decode(String base64url) {
    return UserHandle.of(Base64Url.decode(base64url));
  }
}
