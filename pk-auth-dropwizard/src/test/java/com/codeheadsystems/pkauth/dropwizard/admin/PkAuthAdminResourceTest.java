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
 * Direct unit coverage of {@link PkAuthAdminResource#renameCredential}, whose {@code body == null ?
 * null : body.label()} branch is awkward to reach over HTTP (PATCH isn't supported by the default
 * JAX-RS client connector).
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
  void renameWithNullBodyPassesNullLabel() {
    // The null-body branch forwards a null label, which the service rejects as ValidationFailed.
    when(adminService.renameCredential(eq(USER), eq(USER), any(CredentialId.class), eq(null)))
        .thenReturn(new AdminResult.ValidationFailed<>("label must be non-blank"));
    try (Response r = resource.renameCredential(principal, CRED_B64, null)) {
      assertThat(r.getStatus()).isEqualTo(400);
    }
  }

  @Test
  void constructorRejectsNullService() {
    org.assertj.core.api.Assertions.assertThatThrownBy(() -> new PkAuthAdminResource(null))
        .isInstanceOf(NullPointerException.class);
  }
}
