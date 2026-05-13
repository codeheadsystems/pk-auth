// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.ceremony;

import com.codeheadsystems.pkauth.api.AssertionResult;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.PublicKeyCredentialCreationOptionsJson;
import com.codeheadsystems.pkauth.api.PublicKeyCredentialRequestOptionsJson;
import com.codeheadsystems.pkauth.api.RegistrationResult;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;

/**
 * Framework-neutral entry point for WebAuthn ceremonies. Implemented by the core's {@code
 * DefaultPasskeyAuthenticationService} (Phase 2) and consumed by every framework adapter.
 *
 * <p>No exceptions cross this boundary for ceremony-flow failures — every failure mode is a variant
 * of the relevant {@code *Result} sealed interface. Methods may still throw on programmer errors
 * (null inputs, unconfigured RP, etc.).
 */
public interface PasskeyAuthenticationService {

  /**
   * Issue {@code PublicKeyCredentialCreationOptions} for a new registration and store the matching
   * challenge in the {@code ChallengeStore} for later verification.
   */
  PublicKeyCredentialCreationOptionsJson startRegistration(StartRegistrationRequest req);

  /** Verify a registration response and produce a persistable credential record. */
  RegistrationResult finishRegistration(FinishRegistrationRequest req);

  /**
   * Issue {@code PublicKeyCredentialRequestOptions} for an authentication ceremony and store the
   * matching challenge in the {@code ChallengeStore}.
   */
  PublicKeyCredentialRequestOptionsJson startAuthentication(StartAuthenticationRequest req);

  /** Verify an authentication response. */
  AssertionResult finishAuthentication(FinishAuthenticationRequest req);
}
