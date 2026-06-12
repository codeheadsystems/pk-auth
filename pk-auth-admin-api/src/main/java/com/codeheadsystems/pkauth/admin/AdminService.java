// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.UserHandle;
import java.util.List;

/**
 * Framework-neutral admin operations on a user's pk-auth account (brief §6.9). All authenticated
 * methods take an {@code actor} which the adapter resolves from the JWT subject and apply the
 * configured {@link AdminAuthorizer} before touching the underlying SPIs.
 *
 * @since 0.9.0
 */
public interface AdminService {

  /** Returns the user's account summary (credential count, remaining backup codes, …). */
  AdminResult<AccountSummary> getAccount(UserHandle actor, UserHandle target);

  /** Lists every credential the user has registered. */
  AdminResult<List<CredentialSummary>> listCredentials(UserHandle actor, UserHandle target);

  /** Renames a credential's label. Returns NotFound when the credential is not the user's. */
  AdminResult<CredentialSummary> renameCredential(
      UserHandle actor, UserHandle target, CredentialId credentialId, String newLabel);

  /**
   * Deletes a credential. Refuses if it would leave the user with zero credentials and zero
   * remaining backup codes (unless overridden via {@link AdminSafetyConfig}).
   */
  AdminResult<Void> deleteCredential(
      UserHandle actor, UserHandle target, CredentialId credentialId);

  /**
   * Regenerates the user's backup codes. The plaintext list is returned exactly once; prior codes
   * are atomically invalidated.
   */
  AdminResult<BackupCodesGenerated> regenerateBackupCodes(UserHandle actor, UserHandle target);

  /** Returns how many unconsumed backup codes the user still holds. */
  AdminResult<Integer> remainingBackupCodes(UserHandle actor, UserHandle target);

  /** Sends a verification email to {@code email}. */
  AdminResult<Void> startEmailVerification(UserHandle actor, UserHandle target, String email);

  /**
   * Consumes a magic-link token and marks the user's email verified. Intentionally takes no {@code
   * actor} — the brief mounts this endpoint as unauthenticated.
   *
   * @since 0.9.1
   */
  AdminResult<UserHandle> finishEmailVerification(String token);

  /** Sends an SMS OTP to {@code phoneE164}. */
  AdminResult<OtpDispatchResult> startPhoneVerification(
      UserHandle actor, UserHandle target, String phoneE164);

  /**
   * Verifies an SMS OTP.
   *
   * @since 0.9.1
   */
  AdminResult<PhoneVerificationResult> finishPhoneVerification(
      UserHandle actor, UserHandle target, String phoneE164, String code);
}
