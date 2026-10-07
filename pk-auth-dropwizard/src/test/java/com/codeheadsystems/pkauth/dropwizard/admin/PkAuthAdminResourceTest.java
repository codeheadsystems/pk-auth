// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.codeheadsystems.pkauth.admin.AdminRequests.RenameCredential;
import com.codeheadsystems.pkauth.admin.AdminResult;
import com.codeheadsystems.pkauth.admin.AdminService;
import com.codeheadsystems.pkauth.admin.CredentialSummary;
import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.dropwizard.auth.PkAuthPasskeyPrincipal;
import com.codeheadsystems.pkauth.json.Base64Url;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;

/**
 * Direct unit coverage of {@link PkAuthAdminResource}'s missing-body branches, which are awkward to
 * reach over HTTP (e.g. PATCH is not supported by the default JAX-RS client connector).
 */
class PkAuthAdminResourceTest {

  private static final UserHandle USER = UserHandle.of(new byte[] {1, 2, 3});
  private static final String CRED_B64 = Base64Url.encode(new byte[] {9, 9, 9});
  private final AdminService adminService = mock(AdminService.class);
  private final PkAuthAdminResource resource = new PkAuthAdminResource(adminService);
  private final PkAuthPasskeyPrincipal principal = new PkAuthPasskeyPrincipal(USER, "jti-1");

  @Test
  void renameWithBodyPassesLabelThrough() {
    when(adminService.renameCredential(eq(USER), eq(USER), any(CredentialId.class), eq("Laptop")))
        .thenReturn(new AdminResult.Success<>(mock(CredentialSummary.class)));
    try (Response r =
        resource.renameCredential(principal, CRED_B64, new RenameCredential("Laptop"))) {
      assertThat(r.getStatus()).isEqualTo(200);
    }
  }

  @Test
  void renameWithNullBodyPassesEmptyLabel() {
    // Matches Spring / Micronaut: a missing body forwards "", which the service rejects as
    // ValidationFailed exactly as it would a null label.
    when(adminService.renameCredential(eq(USER), eq(USER), any(CredentialId.class), eq("")))
        .thenReturn(new AdminResult.ValidationFailed<>("label must be non-blank"));
    try (Response r = resource.renameCredential(principal, CRED_B64, null)) {
      assertThat(r.getStatus()).isEqualTo(400);
    }
  }

  @Test
  void emailAndStartPhoneWithNullBodyPassEmptyString() {
    AdminResult.ValidationFailed<Void> invalid = new AdminResult.ValidationFailed<>("invalid");
    when(adminService.startEmailVerification(USER, USER, "")).thenReturn(invalid);
    when(adminService.finishEmailVerification(""))
        .thenReturn(new AdminResult.ValidationFailed<>("token must be non-blank"));
    when(adminService.startPhoneVerification(USER, USER, ""))
        .thenReturn(new AdminResult.ValidationFailed<>("phone must be E.164 format"));

    try (Response r = resource.startEmailVerification(principal, null)) {
      assertThat(r.getStatus()).isEqualTo(400);
    }
    try (Response r = resource.finishEmailVerification(null)) {
      assertThat(r.getStatus()).isEqualTo(400);
    }
    try (Response r = resource.startPhoneVerification(principal, null)) {
      assertThat(r.getStatus()).isEqualTo(400);
    }
  }

  @Test
  void finishPhoneWithNullBodyPassesNulls() {
    // DefaultAdminService rejects a null phone/code up front but would pass "" on to OtpService,
    // so this endpoint keeps forwarding null for a missing body.
    when(adminService.finishPhoneVerification(USER, USER, null, null))
        .thenReturn(new AdminResult.ValidationFailed<>("phone and code are required"));
    try (Response r = resource.finishPhoneVerification(principal, null)) {
      assertThat(r.getStatus()).isEqualTo(400);
    }
  }

  @Test
  void constructorRejectsNullService() {
    org.assertj.core.api.Assertions.assertThatThrownBy(() -> new PkAuthAdminResource(null))
        .isInstanceOf(NullPointerException.class);
  }
}
