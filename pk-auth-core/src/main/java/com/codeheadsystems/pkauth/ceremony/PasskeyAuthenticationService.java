// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.ceremony;

import com.codeheadsystems.pkauth.api.AssertionResult;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.RegistrationResult;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResult;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResult;
import org.jspecify.annotations.Nullable;

/**
 * Framework-neutral entry point for WebAuthn ceremonies. Implemented by the core's {@code
 * DefaultPasskeyAuthenticationService} (Phase 2) and consumed by every framework adapter.
 *
 * <p>No exceptions cross this boundary for ceremony-flow failures — every failure mode is a variant
 * of the relevant {@code *Result} sealed interface. Methods may still throw on programmer errors
 * (null inputs, unconfigured RP, etc.).
 *
 * @since 0.9.0
 */
public interface PasskeyAuthenticationService {

  /**
   * Issue {@code PublicKeyCredentialCreationOptions} for a new registration and store the matching
   * challenge in the {@code ChallengeStore} for later verification. The returned envelope carries
   * both the WebAuthn options the browser consumes and the {@code ChallengeId} the client must
   * round-trip in {@code finishRegistration}.
   */
  default StartRegistrationResult startRegistration(StartRegistrationRequest req) {
    return startRegistration(req, null);
  }

  /**
   * Variant of {@link #startRegistration(StartRegistrationRequest)} that consults the configured
   * {@code CeremonyRateLimiter} against {@code clientIp}. Adapter controllers SHOULD prefer this
   * overload so the per-IP rate limit takes effect; the no-IP overload bypasses the per-IP bucket
   * and is retained for callers (tests, embedded scenarios) that cannot supply a source IP.
   *
   * @param req start request
   * @param clientIp source IP address of the HTTP request, or {@code null} when the host cannot
   *     determine one — the limiter implementation decides how to handle the null case
   * @return start-registration result; {@link StartRegistrationResult.RateLimited} when the limiter
   *     refuses the call (before any challenge is created), otherwise {@link
   *     StartRegistrationResult.Started}
   * @since 0.9.1
   */
  StartRegistrationResult startRegistration(
      StartRegistrationRequest req, @Nullable String clientIp);

  /** Verify a registration response and produce a persistable credential record. */
  default RegistrationResult finishRegistration(FinishRegistrationRequest req) {
    return finishRegistration(req, null);
  }

  /**
   * Variant of {@link #finishRegistration(FinishRegistrationRequest)} that consults the configured
   * {@code CeremonyRateLimiter} against {@code clientIp} before running the WebAuthn attestation
   * verification. Adapter controllers SHOULD prefer this overload so the per-IP rate limit takes
   * effect.
   *
   * @param req finish request
   * @param clientIp source IP address of the HTTP request, or {@code null} when the host cannot
   *     determine one
   * @return registration result; {@link RegistrationResult.RateLimited} when refused
   * @since 0.9.1
   */
  RegistrationResult finishRegistration(FinishRegistrationRequest req, @Nullable String clientIp);

  /**
   * Issue {@code PublicKeyCredentialRequestOptions} for an authentication ceremony and store the
   * matching challenge in the {@code ChallengeStore}. The returned envelope carries both the
   * WebAuthn options the browser consumes and the {@code ChallengeId} the client must round-trip in
   * {@code finishAuthentication}.
   */
  default StartAuthenticationResult startAuthentication(StartAuthenticationRequest req) {
    return startAuthentication(req, null);
  }

  /**
   * Variant of {@link #startAuthentication(StartAuthenticationRequest)} that consults the
   * configured {@code CeremonyRateLimiter} against {@code clientIp}.
   *
   * @param req start request
   * @param clientIp source IP address of the HTTP request, or {@code null} when the host cannot
   *     determine one
   * @return start-authentication result; {@link StartAuthenticationResult.RateLimited} when the
   *     limiter refuses the call (before any challenge is created), otherwise {@link
   *     StartAuthenticationResult.Started}
   * @since 0.9.1
   */
  StartAuthenticationResult startAuthentication(
      StartAuthenticationRequest req, @Nullable String clientIp);

  /** Verify an authentication response. */
  default AssertionResult finishAuthentication(FinishAuthenticationRequest req) {
    return finishAuthentication(req, null);
  }

  /**
   * Variant of {@link #finishAuthentication(FinishAuthenticationRequest)} that consults the
   * configured {@code CeremonyRateLimiter} against {@code clientIp} before running the WebAuthn
   * signature verification.
   *
   * @param req finish request
   * @param clientIp source IP address of the HTTP request, or {@code null} when the host cannot
   *     determine one
   * @return assertion result; {@link AssertionResult.RateLimited} when refused
   * @since 0.9.1
   */
  AssertionResult finishAuthentication(FinishAuthenticationRequest req, @Nullable String clientIp);
}
