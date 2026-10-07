// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh.web;

import com.codeheadsystems.pkauth.jwt.JwtClaims;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.refresh.RefreshTokenService;
import com.codeheadsystems.pkauth.refresh.RotateResult;
import java.util.Objects;

/**
 * Framework-neutral helper that turns a presented refresh token into either a {@link
 * RefreshResponse} (success) or a {@link RefreshErrorResponse} (any of the typed failures). Each
 * adapter's HTTP layer wraps this (Spring's controller, Dropwizard's resource, Micronaut's
 * controller) so the rotation logic and error mapping live in one place.
 *
 * @since 1.1.0
 */
public final class RefreshHandler {

  /** Sealed outcome the adapter pattern-matches into an HTTP response. */
  public sealed interface Outcome {
    record Success(RefreshResponse response) implements Outcome {}

    record Failure(RefreshErrorResponse response) implements Outcome {}
  }

  private final RefreshTokenService refreshService;
  private final PkAuthJwtIssuer accessIssuer;

  public RefreshHandler(RefreshTokenService refreshService, PkAuthJwtIssuer accessIssuer) {
    this.refreshService = Objects.requireNonNull(refreshService, "refreshService");
    this.accessIssuer = Objects.requireNonNull(accessIssuer, "accessIssuer");
  }

  /**
   * Rotates the presented token and, on success, mints an access JWT bound to the rotated audience.
   * The caller maps {@link Outcome.Success} to {@code 200 OK} and {@link Outcome.Failure} to {@code
   * 401 Unauthorized}.
   *
   * <p>Wire-token absence (null / empty body) becomes a {@code unknown} failure rather than a 400
   * so the same response shape covers every error case.
   */
  public Outcome handle(RefreshRequest request) {
    if (request == null || request.refreshToken() == null || request.refreshToken().isBlank()) {
      return new Outcome.Failure(new RefreshErrorResponse("unknown", null));
    }
    RotateResult result = refreshService.rotate(request.refreshToken());
    return switch (result) {
      case RotateResult.Success s -> {
        JwtClaims claims =
            JwtClaims.forRefresh(
                s.claimsForAccessIssue().userHandle(),
                s.claimsForAccessIssue().audience(),
                s.claimsForAccessIssue().amr());
        String accessJwt = accessIssuer.issue(claims);
        yield new Outcome.Success(
            new RefreshResponse(s.pair().wireToken(), accessJwt, s.pair().record().expiresAt()));
      }
      case RotateResult.Expired e -> new Outcome.Failure(new RefreshErrorResponse("expired", null));
      case RotateResult.Unknown u -> new Outcome.Failure(new RefreshErrorResponse("unknown", null));
      case RotateResult.Replayed r ->
          new Outcome.Failure(new RefreshErrorResponse("replayed", null));
      case RotateResult.Revoked rv ->
          new Outcome.Failure(new RefreshErrorResponse("revoked", rv.reason().name()));
    };
  }
}
