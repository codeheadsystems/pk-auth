// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import com.codeheadsystems.pkauth.admin.AdminRequests.FinishEmailVerification;
import com.codeheadsystems.pkauth.admin.AdminRequests.FinishPhoneVerification;
import com.codeheadsystems.pkauth.admin.AdminRequests.RenameCredential;
import com.codeheadsystems.pkauth.admin.AdminRequests.StartEmailVerification;
import com.codeheadsystems.pkauth.admin.AdminRequests.StartPhoneVerification;
import com.codeheadsystems.pkauth.admin.AdminResponseMapper;
import com.codeheadsystems.pkauth.admin.AdminResponseMapper.AdminResponse;
import com.codeheadsystems.pkauth.admin.AdminResult;
import com.codeheadsystems.pkauth.admin.AdminService;
import com.codeheadsystems.pkauth.admin.BackupCodesCountResponse;
import com.codeheadsystems.pkauth.admin.EmailVerificationResult;
import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.UserHandle;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Delete;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Patch;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import org.jspecify.annotations.Nullable;

/**
 * Admin controller mounting the brief §6.9 endpoints under {@code /auth/admin/**}. All
 * authenticated endpoints require the {@link PkAuthJwtAuthenticationFilter} to have attached a user
 * handle to the request; {@code complete-email-verification} is intentionally unauthenticated.
 *
 * <p>Every {@link AdminResult} is routed through {@link AdminResponseMapper} so the JSON shape is
 * byte-for-byte identical across the Spring, Dropwizard, and Micronaut adapters.
 *
 * <p>Mounted only when an {@link AdminService} bean is present — which, because {@code
 * pk-auth-admin-api} is a {@code compileOnly} dependency of this adapter, happens only when the
 * host keeps that module on its runtime classpath. A host that omits it gets no {@code
 * /auth/admin/**} routes at all, matching the optional-admin contract of the Spring Boot starter
 * and the Dropwizard bundle.
 *
 * @since 0.9.1
 */
@Controller("/auth/admin")
@Requires(beans = AdminService.class)
@Produces(MediaType.APPLICATION_JSON)
@ExecuteOn(TaskExecutors.BLOCKING)
public class PkAuthAdminController {

  private final AdminService adminService;

  public PkAuthAdminController(AdminService adminService) {
    this.adminService = adminService;
  }

  @Get("/account")
  public HttpResponse<?> account(HttpRequest<?> request) {
    UserHandle actor = PkAuthJwtAuthenticationFilter.attachedUserHandle(request);
    if (actor == null) return HttpResponse.status(HttpStatus.UNAUTHORIZED);
    return map(adminService.getAccount(actor, actor));
  }

  @Get("/credentials")
  public HttpResponse<?> listCredentials(HttpRequest<?> request) {
    UserHandle actor = PkAuthJwtAuthenticationFilter.attachedUserHandle(request);
    if (actor == null) return HttpResponse.status(HttpStatus.UNAUTHORIZED);
    return map(adminService.listCredentials(actor, actor));
  }

  /** Renames the credential identified by its base64url-encoded id. */
  @Patch("/credentials/{credentialId}")
  public HttpResponse<?> renameCredential(
      HttpRequest<?> request,
      @PathVariable String credentialId,
      @Body @Nullable RenameCredential body) {
    UserHandle actor = PkAuthJwtAuthenticationFilter.attachedUserHandle(request);
    if (actor == null) return HttpResponse.status(HttpStatus.UNAUTHORIZED);
    CredentialId id = CredentialId.fromB64Url(credentialId);
    return map(adminService.renameCredential(actor, actor, id, body == null ? "" : body.label()));
  }

  /** Deletes the credential identified by its base64url-encoded id. */
  @Delete("/credentials/{credentialId}")
  public HttpResponse<?> deleteCredential(
      HttpRequest<?> request, @PathVariable String credentialId) {
    UserHandle actor = PkAuthJwtAuthenticationFilter.attachedUserHandle(request);
    if (actor == null) return HttpResponse.status(HttpStatus.UNAUTHORIZED);
    CredentialId id = CredentialId.fromB64Url(credentialId);
    return map(adminService.deleteCredential(actor, actor, id));
  }

  @Post("/backup-codes/regenerate")
  public HttpResponse<?> regenerateBackupCodes(HttpRequest<?> request) {
    UserHandle actor = PkAuthJwtAuthenticationFilter.attachedUserHandle(request);
    if (actor == null) return HttpResponse.status(HttpStatus.UNAUTHORIZED);
    return map(adminService.regenerateBackupCodes(actor, actor));
  }

  @Get("/backup-codes/count")
  public HttpResponse<?> remainingBackupCodes(HttpRequest<?> request) {
    UserHandle actor = PkAuthJwtAuthenticationFilter.attachedUserHandle(request);
    if (actor == null) return HttpResponse.status(HttpStatus.UNAUTHORIZED);
    return toMicronaut(
        AdminResponseMapper.toResponse(
            adminService.remainingBackupCodes(actor, actor), BackupCodesCountResponse::new));
  }

  @Post("/email/start-verification")
  public HttpResponse<?> startEmailVerification(
      HttpRequest<?> request, @Body @Nullable StartEmailVerification body) {
    UserHandle actor = PkAuthJwtAuthenticationFilter.attachedUserHandle(request);
    if (actor == null) return HttpResponse.status(HttpStatus.UNAUTHORIZED);
    return map(adminService.startEmailVerification(actor, actor, body == null ? "" : body.email()));
  }

  /** Unauthenticated. */
  @Post("/email/complete-verification")
  public HttpResponse<?> finishEmailVerification(@Body @Nullable FinishEmailVerification body) {
    return toMicronaut(
        AdminResponseMapper.toResponse(
            adminService.finishEmailVerification(body == null ? "" : body.token()),
            EmailVerificationResult::new));
  }

  @Post("/phone/start-verification")
  public HttpResponse<?> startPhoneVerification(
      HttpRequest<?> request, @Body @Nullable StartPhoneVerification body) {
    UserHandle actor = PkAuthJwtAuthenticationFilter.attachedUserHandle(request);
    if (actor == null) return HttpResponse.status(HttpStatus.UNAUTHORIZED);
    return map(adminService.startPhoneVerification(actor, actor, body == null ? "" : body.phone()));
  }

  @Post("/phone/complete-verification")
  public HttpResponse<?> finishPhoneVerification(
      HttpRequest<?> request, @Body @Nullable FinishPhoneVerification body) {
    UserHandle actor = PkAuthJwtAuthenticationFilter.attachedUserHandle(request);
    if (actor == null) return HttpResponse.status(HttpStatus.UNAUTHORIZED);
    return map(
        adminService.finishPhoneVerification(
            actor, actor, body == null ? "" : body.phone(), body == null ? "" : body.code()));
  }

  /**
   * Maps an {@link AdminResult} to a Micronaut {@link HttpResponse} via the shared {@link
   * AdminResponseMapper}. Kept on the controller for backwards-compat with existing tests.
   */
  static HttpResponse<?> map(AdminResult<?> result) {
    return toMicronaut(AdminResponseMapper.toResponse(result));
  }

  private static HttpResponse<?> toMicronaut(AdminResponse response) {
    MutableHttpResponse<Object> http = HttpResponse.status(HttpStatus.valueOf(response.status()));
    response.headers().forEach(http::header);
    if (response.body() != null) {
      http.body(response.body());
    }
    return http;
  }
}
