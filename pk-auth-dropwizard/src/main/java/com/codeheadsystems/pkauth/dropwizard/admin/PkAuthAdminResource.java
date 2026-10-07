// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.admin;

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
import com.codeheadsystems.pkauth.dropwizard.auth.PkAuthPasskeyPrincipal;
import io.dropwizard.auth.Auth;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * HTTP exposure of {@link AdminService}. Mounted at {@code /auth/admin} by the bundle when {@code
 * pk-auth-admin-api} is on the classpath. Every {@link
 * com.codeheadsystems.pkauth.admin.AdminResult} is routed through {@link AdminResponseMapper} (via
 * {@link PkAuthAdminResultMapper}) so the JSON shape is byte-for-byte identical across the Spring,
 * Dropwizard, and Micronaut adapters.
 *
 * @since 0.9.1
 */
@Path("/auth/admin")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class PkAuthAdminResource {

  private final AdminService adminService;

  @Inject
  public PkAuthAdminResource(AdminService adminService) {
    this.adminService = Objects.requireNonNull(adminService, "adminService");
  }

  @GET
  @Path("/account")
  public Response getAccount(@Auth PkAuthPasskeyPrincipal principal) {
    UserHandle user = principal.userHandle();
    return PkAuthAdminResultMapper.toResponse(adminService.getAccount(user, user));
  }

  @GET
  @Path("/credentials")
  public Response listCredentials(@Auth PkAuthPasskeyPrincipal principal) {
    UserHandle user = principal.userHandle();
    return PkAuthAdminResultMapper.toResponse(adminService.listCredentials(user, user));
  }

  @PATCH
  @Path("/credentials/{credentialId}")
  public Response renameCredential(
      @Auth PkAuthPasskeyPrincipal principal,
      @PathParam("credentialId") String credentialIdB64Url,
      @Nullable RenameCredential body) {
    UserHandle user = principal.userHandle();
    CredentialId id = CredentialId.fromB64Url(credentialIdB64Url);
    return PkAuthAdminResultMapper.toResponse(
        adminService.renameCredential(user, user, id, body == null ? "" : body.label()));
  }

  @DELETE
  @Path("/credentials/{credentialId}")
  public Response deleteCredential(
      @Auth PkAuthPasskeyPrincipal principal,
      @PathParam("credentialId") String credentialIdB64Url) {
    UserHandle user = principal.userHandle();
    CredentialId id = CredentialId.fromB64Url(credentialIdB64Url);
    return PkAuthAdminResultMapper.toResponse(adminService.deleteCredential(user, user, id));
  }

  @POST
  @Path("/backup-codes/regenerate")
  public Response regenerateBackupCodes(@Auth PkAuthPasskeyPrincipal principal) {
    UserHandle user = principal.userHandle();
    return PkAuthAdminResultMapper.toResponse(adminService.regenerateBackupCodes(user, user));
  }

  @GET
  @Path("/backup-codes/count")
  public Response remainingBackupCodes(@Auth PkAuthPasskeyPrincipal principal) {
    UserHandle user = principal.userHandle();
    return PkAuthAdminResultMapper.toResponse(
        AdminResponseMapper.toResponse(
            adminService.remainingBackupCodes(user, user), BackupCodesCountResponse::new));
  }

  @POST
  @Path("/email/start-verification")
  public Response startEmailVerification(
      @Auth PkAuthPasskeyPrincipal principal, @Nullable StartEmailVerification body) {
    UserHandle user = principal.userHandle();
    return PkAuthAdminResultMapper.toResponse(
        adminService.startEmailVerification(user, user, body == null ? "" : body.email()));
  }

  /** Brief §6.9 mounts the complete-verification endpoint as unauthenticated. */
  @POST
  @Path("/email/complete-verification")
  public Response finishEmailVerification(@Nullable FinishEmailVerification body) {
    return PkAuthAdminResultMapper.toResponse(
        AdminResponseMapper.toResponse(
            adminService.finishEmailVerification(body == null ? "" : body.token()),
            EmailVerificationResult::new));
  }

  @POST
  @Path("/phone/start-verification")
  public Response startPhoneVerification(
      @Auth PkAuthPasskeyPrincipal principal, @Nullable StartPhoneVerification body) {
    UserHandle user = principal.userHandle();
    return PkAuthAdminResultMapper.toResponse(
        adminService.startPhoneVerification(user, user, body == null ? "" : body.phone()));
  }

  @POST
  @Path("/phone/complete-verification")
  public Response finishPhoneVerification(
      @Auth PkAuthPasskeyPrincipal principal, @Nullable FinishPhoneVerification body) {
    UserHandle user = principal.userHandle();
    // A missing body passes null, not "" as for the other endpoints: DefaultAdminService rejects a
    // null phone/code as ValidationFailed but would hand "" through to OtpService.
    String phone = body == null ? null : body.phone();
    String code = body == null ? null : body.code();
    return PkAuthAdminResultMapper.toResponse(
        adminService.finishPhoneVerification(user, user, phone, code));
  }
}
