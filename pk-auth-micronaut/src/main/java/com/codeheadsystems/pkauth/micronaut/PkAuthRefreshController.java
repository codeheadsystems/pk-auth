// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import com.codeheadsystems.pkauth.refresh.web.RefreshHandler;
import com.codeheadsystems.pkauth.refresh.web.RefreshHandler.Outcome;
import com.codeheadsystems.pkauth.refresh.web.RefreshRequest;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;

/**
 * Mounts the refresh endpoint at {@code POST /auth/refresh}. Only registered when a {@link
 * RefreshHandler} bean is present (which itself requires a {@code RefreshTokenRepository}). The
 * controller is a thin wrapper around the shared handler; rotation logic and error mapping live in
 * {@code pk-auth-refresh-tokens}.
 *
 * @since 1.1.0
 */
@Controller("/auth/refresh")
@Produces(MediaType.APPLICATION_JSON)
@ExecuteOn(TaskExecutors.BLOCKING)
@Requires(beans = RefreshHandler.class)
public final class PkAuthRefreshController {

  private final RefreshHandler handler;

  public PkAuthRefreshController(RefreshHandler handler) {
    this.handler = handler;
  }

  @Post
  public HttpResponse<Object> refresh(@Body RefreshRequest request) {
    Outcome outcome = handler.handle(request);
    return switch (outcome) {
      case Outcome.Success s -> HttpResponse.ok(s.response());
      case Outcome.Failure f ->
          HttpResponse.<Object>status(HttpStatus.UNAUTHORIZED).body(f.response());
    };
  }
}
