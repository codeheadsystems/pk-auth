// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.web;

import com.codeheadsystems.pkauth.api.CeremonyWireMapper.CeremonyResponse;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResult;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResult;
import com.codeheadsystems.pkauth.jwt.CeremonyOrchestrator;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Mounts the four ceremony endpoints under {@code /auth/passkeys}. Every endpoint delegates to
 * {@link CeremonyOrchestrator}, which owns the JWT-mint / label-lookup / wire-mapping pipeline and
 * is shared byte-for-byte across the Spring, Dropwizard, and Micronaut adapters.
 */
@RestController
@RequestMapping("/auth/passkeys")
public class PkAuthCeremonyController {

  private static final Logger LOG = LoggerFactory.getLogger(PkAuthCeremonyController.class);

  private final CeremonyOrchestrator orchestrator;

  public PkAuthCeremonyController(CeremonyOrchestrator orchestrator) {
    this.orchestrator = orchestrator;
  }

  @PostMapping("/registration/start")
  public ResponseEntity<Object> startRegistration(
      @RequestBody StartRegistrationRequest req, HttpServletRequest httpRequest) {
    LOG.debug("auth.registration.start username={}", req.username());
    return switch (orchestrator.startRegistration(req, clientIp(httpRequest))) {
      case StartRegistrationResult.Started started -> ResponseEntity.ok(started.response());
      case StartRegistrationResult.RateLimited rl -> {
        LOG.info("auth.registration.start rate-limited bucket={}", rl.bucket());
        yield toResponseEntity(orchestrator.rateLimited());
      }
    };
  }

  @PostMapping("/registration/finish")
  public ResponseEntity<Object> finishRegistration(
      @RequestBody FinishRegistrationRequest req, HttpServletRequest httpRequest) {
    return toResponseEntity(orchestrator.finishRegistration(req, clientIp(httpRequest)));
  }

  @PostMapping("/authentication/start")
  public ResponseEntity<Object> startAuthentication(
      @RequestBody StartAuthenticationRequest req, HttpServletRequest httpRequest) {
    LOG.debug("auth.authentication.start username={}", req.username());
    return switch (orchestrator.startAuthentication(req, clientIp(httpRequest))) {
      case StartAuthenticationResult.Started started -> ResponseEntity.ok(started.response());
      case StartAuthenticationResult.RateLimited rl -> {
        LOG.info("auth.authentication.start rate-limited bucket={}", rl.bucket());
        yield toResponseEntity(orchestrator.rateLimited());
      }
    };
  }

  @PostMapping("/authentication/finish")
  public ResponseEntity<Object> finishAuthentication(
      @RequestBody FinishAuthenticationRequest req, HttpServletRequest httpRequest) {
    return toResponseEntity(orchestrator.finishAuthentication(req, clientIp(httpRequest)));
  }

  private static ResponseEntity<Object> toResponseEntity(CeremonyResponse wire) {
    return ResponseEntity.status(wire.status()).body(wire.body());
  }

  private static @Nullable String clientIp(HttpServletRequest request) {
    return request.getRemoteAddr();
  }
}
