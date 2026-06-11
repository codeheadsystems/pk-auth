// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.admin;

import com.codeheadsystems.pkauth.admin.AdminRequests.FinishEmailVerification;
import com.codeheadsystems.pkauth.admin.AdminRequests.FinishPhoneVerification;
import com.codeheadsystems.pkauth.admin.AdminRequests.RenameCredential;
import com.codeheadsystems.pkauth.admin.AdminRequests.StartEmailVerification;
import com.codeheadsystems.pkauth.admin.AdminRequests.StartPhoneVerification;
import com.codeheadsystems.pkauth.admin.AdminResponseMapper;
import com.codeheadsystems.pkauth.admin.AdminService;
import com.codeheadsystems.pkauth.admin.BackupCodesCountResponse;
import com.codeheadsystems.pkauth.admin.EmailVerificationResult;
import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spring.security.PkAuthJwtAuthenticationToken;
import org.jspecify.annotations.Nullable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST adapter for {@link AdminService}. Mounted under {@code /auth/admin} per brief §6.9 endpoint
 * table. Every {@link com.codeheadsystems.pkauth.admin.AdminResult} is routed through {@link
 * AdminResponseMapper} (via {@link PkAuthAdminResultMapper}) so the JSON shape is byte-for-byte
 * identical across the Spring, Dropwizard, and Micronaut adapters.
 *
 * @since 0.9.1
 */
@RestController
@RequestMapping("/auth/admin")
public class PkAuthAdminController {

  private final AdminService adminService;

  public PkAuthAdminController(AdminService adminService) {
    this.adminService = adminService;
  }

  // -- Account ---------------------------------------------------------------------------------

  @GetMapping("/account")
  public ResponseEntity<Object> account() {
    UserHandle user = currentUser();
    return PkAuthAdminResultMapper.toResponse(adminService.getAccount(user, user));
  }

  // -- Credentials -----------------------------------------------------------------------------

  @GetMapping("/credentials")
  public ResponseEntity<Object> listCredentials() {
    UserHandle user = currentUser();
    return PkAuthAdminResultMapper.toResponse(adminService.listCredentials(user, user));
  }

  @PatchMapping("/credentials/{credentialId}")
  public ResponseEntity<Object> rename(
      @PathVariable("credentialId") String credentialId,
      @RequestBody @Nullable RenameCredential body) {
    UserHandle user = currentUser();
    CredentialId id = CredentialId.fromB64Url(credentialId);
    return PkAuthAdminResultMapper.toResponse(
        adminService.renameCredential(user, user, id, body == null ? "" : body.label()));
  }

  @DeleteMapping("/credentials/{credentialId}")
  public ResponseEntity<Object> delete(@PathVariable("credentialId") String credentialId) {
    UserHandle user = currentUser();
    CredentialId id = CredentialId.fromB64Url(credentialId);
    return PkAuthAdminResultMapper.toResponse(adminService.deleteCredential(user, user, id));
  }

  // -- Backup codes ----------------------------------------------------------------------------

  @PostMapping("/backup-codes/regenerate")
  public ResponseEntity<Object> regenerateBackupCodes() {
    UserHandle user = currentUser();
    return PkAuthAdminResultMapper.toResponse(adminService.regenerateBackupCodes(user, user));
  }

  @GetMapping("/backup-codes/count")
  public ResponseEntity<Object> remainingBackupCodes() {
    UserHandle user = currentUser();
    return PkAuthAdminResultMapper.toResponseEntity(
        AdminResponseMapper.toResponse(
            adminService.remainingBackupCodes(user, user), BackupCodesCountResponse::new));
  }

  // -- Email -----------------------------------------------------------------------------------

  @PostMapping("/email/start-verification")
  public ResponseEntity<Object> startEmailVerification(
      @RequestBody @Nullable StartEmailVerification body) {
    UserHandle user = currentUser();
    return PkAuthAdminResultMapper.toResponse(
        adminService.startEmailVerification(user, user, body == null ? "" : body.email()));
  }

  /** Unauthenticated per brief §6.9 ("token identifies the user"). */
  @PostMapping("/email/complete-verification")
  public ResponseEntity<Object> finishEmailVerification(
      @RequestBody @Nullable FinishEmailVerification body) {
    return PkAuthAdminResultMapper.toResponseEntity(
        AdminResponseMapper.toResponse(
            adminService.finishEmailVerification(body == null ? "" : body.token()),
            EmailVerificationResult::new));
  }

  // -- Phone -----------------------------------------------------------------------------------

  @PostMapping("/phone/start-verification")
  public ResponseEntity<Object> startPhoneVerification(
      @RequestBody @Nullable StartPhoneVerification body) {
    UserHandle user = currentUser();
    return PkAuthAdminResultMapper.toResponse(
        adminService.startPhoneVerification(user, user, body == null ? "" : body.phone()));
  }

  @PostMapping("/phone/complete-verification")
  public ResponseEntity<Object> finishPhoneVerification(
      @RequestBody @Nullable FinishPhoneVerification body) {
    UserHandle user = currentUser();
    return PkAuthAdminResultMapper.toResponse(
        adminService.finishPhoneVerification(
            user, user, body == null ? "" : body.phone(), body == null ? "" : body.code()));
  }

  // -- helpers ---------------------------------------------------------------------------------

  private UserHandle currentUser() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth instanceof PkAuthJwtAuthenticationToken pkAuthToken && pkAuthToken.isAuthenticated()) {
      return pkAuthToken.getPrincipal();
    }
    throw new AccessDeniedException("Authenticated pk-auth JWT required");
  }
}
