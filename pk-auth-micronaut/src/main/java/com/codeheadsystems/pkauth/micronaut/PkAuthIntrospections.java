// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import com.codeheadsystems.pkauth.admin.AccountSummary;
import com.codeheadsystems.pkauth.admin.AdminRequests;
import com.codeheadsystems.pkauth.admin.AdminResult;
import com.codeheadsystems.pkauth.admin.BackupCodesCountResponse;
import com.codeheadsystems.pkauth.admin.BackupCodesGenerated;
import com.codeheadsystems.pkauth.admin.CredentialSummary;
import com.codeheadsystems.pkauth.admin.EmailVerificationResult;
import com.codeheadsystems.pkauth.admin.OtpDispatchResult;
import com.codeheadsystems.pkauth.admin.PhoneVerificationResult;
import com.codeheadsystems.pkauth.api.AssertionResult;
import com.codeheadsystems.pkauth.api.AuthenticationResponseJson;
import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.PublicKeyCredentialCreationOptionsJson;
import com.codeheadsystems.pkauth.api.PublicKeyCredentialRequestOptionsJson;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson;
import com.codeheadsystems.pkauth.api.RegistrationResult;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResponse;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResponse;
import com.codeheadsystems.pkauth.api.Transport;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.credential.AuthenticatorData;
import com.codeheadsystems.pkauth.credential.CredentialMetadata;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import io.micronaut.core.annotation.Introspected;

/**
 * Registers Micronaut bean-introspection metadata for every pk-auth wire type that crosses the
 * Micronaut serialisation boundary. The records live in {@code pk-auth-core} so they cannot be
 * annotated in place; the {@code @Introspected(classes = …)} sweep on this placeholder class
 * teaches Micronaut's compile-time processor to generate introspection adapters for each one.
 */
@Introspected(
    classes = {
      // ceremony request/response
      StartRegistrationRequest.class,
      StartRegistrationResponse.class,
      FinishRegistrationRequest.class,
      StartAuthenticationRequest.class,
      StartAuthenticationResponse.class,
      FinishAuthenticationRequest.class,
      RegistrationResponseJson.class,
      RegistrationResponseJson.AuthenticatorAttestationResponseJson.class,
      AuthenticationResponseJson.class,
      AuthenticationResponseJson.AuthenticatorAssertionResponseJson.class,
      PublicKeyCredentialCreationOptionsJson.class,
      PublicKeyCredentialCreationOptionsJson.RelyingParty.class,
      PublicKeyCredentialCreationOptionsJson.UserInfo.class,
      PublicKeyCredentialCreationOptionsJson.PublicKeyCredentialParameters.class,
      PublicKeyCredentialCreationOptionsJson.PublicKeyCredentialDescriptor.class,
      PublicKeyCredentialCreationOptionsJson.AuthenticatorSelectionCriteria.class,
      PublicKeyCredentialRequestOptionsJson.class,
      // results
      RegistrationResult.class,
      RegistrationResult.Success.class,
      RegistrationResult.InvalidChallenge.class,
      RegistrationResult.OriginMismatch.class,
      RegistrationResult.AttestationRejected.class,
      RegistrationResult.DuplicateCredential.class,
      RegistrationResult.InvalidPayload.class,
      RegistrationResult.RateLimited.class,
      AssertionResult.class,
      AssertionResult.Success.class,
      AssertionResult.UnknownCredential.class,
      AssertionResult.InvalidChallenge.class,
      AssertionResult.OriginMismatch.class,
      AssertionResult.CounterRegression.class,
      AssertionResult.UserVerificationRequired.class,
      AssertionResult.InvalidSignature.class,
      AssertionResult.RateLimited.class,
      // value types
      UserHandle.class,
      ChallengeId.class,
      CredentialId.class,
      Transport.class,
      CredentialRecord.class,
      CredentialMetadata.class,
      AuthenticatorData.class,
      // admin
      AccountSummary.class,
      CredentialSummary.class,
      BackupCodesGenerated.class,
      OtpDispatchResult.class,
      PhoneVerificationResult.class,
      PhoneVerificationResult.Verified.class,
      PhoneVerificationResult.Mismatch.class,
      PhoneVerificationResult.Expired.class,
      PhoneVerificationResult.AttemptsExceeded.class,
      AdminResult.Success.class,
      AdminResult.NotFound.class,
      AdminResult.Forbidden.class,
      AdminResult.ValidationFailed.class,
      AdminResult.Conflict.class,
      AdminResult.RateLimited.class,
      // shared admin wire DTOs (items #10, #11)
      AdminRequests.RenameCredential.class,
      AdminRequests.StartEmailVerification.class,
      AdminRequests.FinishEmailVerification.class,
      AdminRequests.StartPhoneVerification.class,
      AdminRequests.FinishPhoneVerification.class,
      BackupCodesCountResponse.class,
      EmailVerificationResult.class,
    })
public final class PkAuthIntrospections {
  private PkAuthIntrospections() {}
}
