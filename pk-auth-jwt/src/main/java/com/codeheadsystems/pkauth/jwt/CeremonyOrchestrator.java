// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import com.codeheadsystems.pkauth.api.AssertionResult;
import com.codeheadsystems.pkauth.api.CeremonyWireMapper;
import com.codeheadsystems.pkauth.api.CeremonyWireMapper.CeremonyResponse;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.RegistrationResult;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResult;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResult;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import java.util.Objects;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Framework-neutral orchestrator for the four WebAuthn ceremony endpoints. Adapters (Spring,
 * Dropwizard, Micronaut) hold a single instance of this class and delegate each endpoint to one
 * method here, so the post-processing — JWT minting on a successful assertion, credential-label
 * lookup, and {@link CeremonyWireMapper} dispatch — lives in exactly one place.
 *
 * <p>Before this helper existed each adapter's controller hand-rolled the same
 * finish-authentication pipeline (call service, switch on {@link AssertionResult}, mint JWT, look
 * up label, map to wire shape), with subtle drift between them. This orchestrator removes that
 * drift.
 *
 * <p>{@code start*} endpoints are pass-throughs to {@link PasskeyAuthenticationService}; they live
 * here purely for symmetry so adapters can hold one dependency instead of three.
 *
 * @since 0.9.1
 */
public final class CeremonyOrchestrator {

  private static final Logger LOG = LoggerFactory.getLogger(CeremonyOrchestrator.class);

  private final PasskeyAuthenticationService service;
  private final PkAuthJwtIssuer issuer;
  private final CredentialRepository credentialRepository;

  public CeremonyOrchestrator(
      PasskeyAuthenticationService service,
      PkAuthJwtIssuer issuer,
      CredentialRepository credentialRepository) {
    this.service = Objects.requireNonNull(service, "service");
    this.issuer = Objects.requireNonNull(issuer, "issuer");
    this.credentialRepository =
        Objects.requireNonNull(credentialRepository, "credentialRepository");
  }

  /** Delegates to {@link PasskeyAuthenticationService#startRegistration}. */
  public StartRegistrationResult startRegistration(
      StartRegistrationRequest request, @Nullable String clientIp) {
    return service.startRegistration(request, clientIp);
  }

  /** Delegates to {@link PasskeyAuthenticationService#startAuthentication}. */
  public StartAuthenticationResult startAuthentication(
      StartAuthenticationRequest request, @Nullable String clientIp) {
    return service.startAuthentication(request, clientIp);
  }

  /**
   * Runs {@link PasskeyAuthenticationService#finishRegistration} and maps the result via {@link
   * CeremonyWireMapper#forRegistration}. Logs the success event at INFO so all three adapters emit
   * an identical "registration succeeded" line.
   */
  public CeremonyResponse finishRegistration(
      FinishRegistrationRequest request, @Nullable String clientIp) {
    RegistrationResult result = service.finishRegistration(request, clientIp);
    if (result instanceof RegistrationResult.Success success) {
      LOG.info(
          "auth.registration.success user={} credentialId={}",
          success.credential().userHandle(),
          success.credential().credentialId().b64url());
    }
    return CeremonyWireMapper.forRegistration(result);
  }

  /**
   * Runs {@link PasskeyAuthenticationService#finishAuthentication} and shapes the response. On
   * {@link AssertionResult.Success} mints a JWT via {@link PkAuthCeremonyJwt#mintForAssertion},
   * looks up the credential label from {@link CredentialRepository} (falling back to {@code null}
   * on the rare delete-between-assertion-and-lookup race), and embeds both in the wire body.
   */
  public CeremonyResponse finishAuthentication(
      FinishAuthenticationRequest request, @Nullable String clientIp) {
    AssertionResult result = service.finishAuthentication(request, clientIp);
    if (result instanceof AssertionResult.Success success) {
      String token = PkAuthCeremonyJwt.mintForAssertion(success, issuer);
      String label =
          credentialRepository
              .findByCredentialId(success.credentialId())
              .map(CredentialRecord::label)
              .orElse(null);
      LOG.info(
          "auth.authentication.success user={} credentialId={} signCount={}",
          success.userHandle(),
          success.credentialId().b64url(),
          success.signCount());
      return CeremonyWireMapper.forAssertionSuccess(success, token, label);
    }
    return CeremonyWireMapper.forAssertionError(result);
  }

  /**
   * Canonical wire shape (HTTP {@code 429}) for a {@code start*} ceremony rate-limit refusal.
   * Adapter controllers call this for the {@code RateLimited} variant of {@link
   * com.codeheadsystems.pkauth.api.StartRegistrationResult} / {@link
   * com.codeheadsystems.pkauth.api.StartAuthenticationResult}.
   */
  public CeremonyResponse rateLimited() {
    return CeremonyWireMapper.rateLimited();
  }
}
