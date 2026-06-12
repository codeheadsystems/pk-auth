// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.resource;

import com.codeheadsystems.pkauth.api.CeremonyWireMapper.CeremonyResponse;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResult;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResult;
import com.codeheadsystems.pkauth.jwt.CeremonyOrchestrator;
import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The four WebAuthn ceremony endpoints. Mounted under {@code /auth/passkeys} — same path scheme as
 * the Spring and Micronaut adapters. Every endpoint delegates to {@link CeremonyOrchestrator},
 * which owns the JWT-mint / label-lookup / wire-mapping pipeline shared across adapters.
 */
@Path("/auth/passkeys")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class PkAuthCeremonyResource {

  private static final Logger LOG = LoggerFactory.getLogger(PkAuthCeremonyResource.class);

  private final CeremonyOrchestrator orchestrator;

  @Inject
  public PkAuthCeremonyResource(CeremonyOrchestrator orchestrator) {
    this.orchestrator = Objects.requireNonNull(orchestrator, "orchestrator");
  }

  @POST
  @Path("/registration/start")
  public Response startRegistration(
      StartRegistrationRequest request, @Context HttpServletRequest httpRequest) {
    return switch (orchestrator.startRegistration(request, clientIp(httpRequest))) {
      case StartRegistrationResult.Started started -> Response.ok(started.response()).build();
      case StartRegistrationResult.RateLimited rl -> rateLimitedResponse(rl.bucket());
    };
  }

  @POST
  @Path("/registration/finish")
  public Response finishRegistration(
      FinishRegistrationRequest request, @Context HttpServletRequest httpRequest) {
    return toResponse(orchestrator.finishRegistration(request, clientIp(httpRequest)));
  }

  @POST
  @Path("/authentication/start")
  public Response startAuthentication(
      StartAuthenticationRequest request, @Context HttpServletRequest httpRequest) {
    return switch (orchestrator.startAuthentication(request, clientIp(httpRequest))) {
      case StartAuthenticationResult.Started started -> Response.ok(started.response()).build();
      case StartAuthenticationResult.RateLimited rl -> rateLimitedResponse(rl.bucket());
    };
  }

  @POST
  @Path("/authentication/finish")
  public Response finishAuthentication(
      FinishAuthenticationRequest request, @Context HttpServletRequest httpRequest) {
    return toResponse(orchestrator.finishAuthentication(request, clientIp(httpRequest)));
  }

  private static Response toResponse(CeremonyResponse wire) {
    return Response.status(wire.status()).entity(wire.body()).build();
  }

  private static String clientIp(HttpServletRequest httpRequest) {
    return httpRequest == null ? null : httpRequest.getRemoteAddr();
  }

  private Response rateLimitedResponse(String bucket) {
    LOG.info("auth.ceremony rate-limited bucket={}", bucket);
    return toResponse(orchestrator.rateLimited());
  }
}
