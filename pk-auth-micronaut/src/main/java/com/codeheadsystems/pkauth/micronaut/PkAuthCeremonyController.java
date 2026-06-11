// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import com.codeheadsystems.pkauth.api.CeremonyWireMapper.CeremonyResponse;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResponse;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResponse;
import com.codeheadsystems.pkauth.jwt.CeremonyOrchestrator;
import com.codeheadsystems.pkauth.spi.CeremonyRateLimitedException;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Error;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import java.net.InetSocketAddress;
import java.util.Map;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Mounts the four WebAuthn ceremony endpoints under {@code /auth/passkeys/**} — same path scheme as
 * the Spring and Dropwizard adapters. Every endpoint delegates to {@link CeremonyOrchestrator},
 * which owns the JWT-mint / label-lookup / wire-mapping pipeline shared across adapters.
 *
 * <p><b>Threading.</b> pk-auth's SPI is blocking (JDBC, DynamoDB SDK, etc.); this adapter
 * dispatches every endpoint to {@link TaskExecutors#BLOCKING} so Micronaut's Netty event loop is
 * never parked on a synchronous repository call.
 */
@Controller("/auth/passkeys")
@Produces(MediaType.APPLICATION_JSON)
@ExecuteOn(TaskExecutors.BLOCKING)
public class PkAuthCeremonyController {

  private static final Logger LOG = LoggerFactory.getLogger(PkAuthCeremonyController.class);

  private final CeremonyOrchestrator orchestrator;

  public PkAuthCeremonyController(CeremonyOrchestrator orchestrator) {
    this.orchestrator = orchestrator;
  }

  @Post("/registration/start")
  public HttpResponse<StartRegistrationResponse> startRegistration(
      @Body StartRegistrationRequest req, HttpRequest<?> httpRequest) {
    return HttpResponse.ok(orchestrator.startRegistration(req, clientIp(httpRequest)));
  }

  @Post("/registration/finish")
  public HttpResponse<Map<String, Object>> finishRegistration(
      @Body FinishRegistrationRequest req, HttpRequest<?> httpRequest) {
    return toResponse(orchestrator.finishRegistration(req, clientIp(httpRequest)));
  }

  @Post("/authentication/start")
  public HttpResponse<StartAuthenticationResponse> startAuthentication(
      @Body StartAuthenticationRequest req, HttpRequest<?> httpRequest) {
    return HttpResponse.ok(orchestrator.startAuthentication(req, clientIp(httpRequest)));
  }

  @Post("/authentication/finish")
  public HttpResponse<Map<String, Object>> finishAuthentication(
      @Body FinishAuthenticationRequest req, HttpRequest<?> httpRequest) {
    return toResponse(orchestrator.finishAuthentication(req, clientIp(httpRequest)));
  }

  /**
   * Maps a {@link CeremonyRateLimitedException} thrown by {@code startRegistration} / {@code
   * startAuthentication} to the canonical {@code 429} wire shape.
   *
   * @since 0.9.1
   */
  @Error(exception = CeremonyRateLimitedException.class)
  public HttpResponse<Map<String, Object>> handleRateLimited(CeremonyRateLimitedException ex) {
    LOG.info("auth.ceremony rate-limited bucket={}", ex.bucket());
    return toResponse(orchestrator.rateLimited());
  }

  private static HttpResponse<Map<String, Object>> toResponse(CeremonyResponse wire) {
    return HttpResponse.<Map<String, Object>>status(HttpStatus.valueOf(wire.status()))
        .body(wire.body());
  }

  private static @Nullable String clientIp(HttpRequest<?> request) {
    InetSocketAddress addr = request.getRemoteAddress();
    if (addr == null || addr.getAddress() == null) {
      return null;
    }
    return addr.getAddress().getHostAddress();
  }
}
