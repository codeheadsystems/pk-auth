// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.jwt.JwtClaims;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.spi.UserLookup;
import io.micronaut.context.annotation.Property;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import java.util.List;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Drives the authenticated admin endpoints the smoke tests don't reach, covering the {@code actor
 * != null} happy branch and the non-null request-body path of each handler.
 */
@MicronautTest
@Property(name = "pkauth.relying-party.id", value = "example.com")
@Property(name = "pkauth.relying-party.name", value = "test")
@Property(name = "pkauth.relying-party.origins[0]", value = "https://example.com")
@Property(name = "pkauth.jwt.issuer", value = "https://pkauth.example.com")
@Property(name = "pkauth.jwt.audience", value = "https://app.example.com")
@Property(name = "pkauth.jwt.secret", value = "pk-auth-micronaut-test-secret-32b!")
@Property(name = "pkauth.dev-mode", value = "true")
class PkAuthAdminEndpointsCoverageTest {

  @Inject
  @Client("/")
  HttpClient client;

  @Inject PkAuthJwtIssuer issuer;
  @Inject UserLookup users;

  private String tokenFor(String username) {
    UserHandle uh = users.getOrCreateHandle(username);
    return issuer.issue(JwtClaims.forBackupCode(uh, List.of("test")));
  }

  private int status(HttpRequest<?> req) {
    HttpResponse<String> resp = client.toBlocking().exchange(req, String.class);
    return resp.getStatus().getCode();
  }

  @Test
  void listCredentialsReturnsOkEmptyArrayForFreshUser() {
    HttpResponse<String> resp =
        client
            .toBlocking()
            .exchange(
                HttpRequest.GET("/auth/admin/credentials").bearerAuth(tokenFor("list-user")),
                String.class);
    Assertions.assertThat(resp.getStatus().getCode()).isEqualTo(HttpStatus.OK.getCode());
    Assertions.assertThat(resp.body()).startsWith("[");
  }

  @Test
  void remainingBackupCodesCountReturnsOk() {
    Assertions.assertThat(
            status(
                HttpRequest.GET("/auth/admin/backup-codes/count")
                    .bearerAuth(tokenFor("count-user"))))
        .isEqualTo(HttpStatus.OK.getCode());
  }

  @Test
  void startEmailVerificationWithValidEmailReturnsNoContent() {
    // Privacy invariant: a successful (or email-mismatch) send returns 204 with no body so a
    // caller can't probe which address is bound to the user.
    Assertions.assertThat(
            status(
                HttpRequest.POST(
                        "/auth/admin/email/start-verification", "{\"email\":\"alice@example.com\"}")
                    .bearerAuth(tokenFor("email-user"))
                    .contentType(MediaType.APPLICATION_JSON)))
        .isEqualTo(HttpStatus.NO_CONTENT.getCode());
  }

  @Test
  void finishPhoneVerificationWithNoActiveOtpReturnsOkExpired() {
    HttpResponse<String> resp =
        client
            .toBlocking()
            .exchange(
                HttpRequest.POST(
                        "/auth/admin/phone/complete-verification",
                        "{\"phone\":\"+15557654321\",\"code\":\"000000\"}")
                    .bearerAuth(tokenFor("phone-finish-user"))
                    .contentType(MediaType.APPLICATION_JSON),
                String.class);
    Assertions.assertThat(resp.getStatus().getCode()).isEqualTo(HttpStatus.OK.getCode());
  }

  @Test
  void renameUnknownCredentialReturnsNotFound() {
    HttpClientResponseException ex =
        org.junit.jupiter.api.Assertions.assertThrows(
            HttpClientResponseException.class,
            () ->
                client
                    .toBlocking()
                    .exchange(
                        HttpRequest.PATCH(
                                "/auth/admin/credentials/" + Base64Url.encode(new byte[] {1, 2, 3}),
                                "{\"label\":\"Renamed\"}")
                            .bearerAuth(tokenFor("rename-user"))
                            .contentType(MediaType.APPLICATION_JSON)));
    Assertions.assertThat(ex.getStatus().getCode()).isEqualTo(HttpStatus.NOT_FOUND.getCode());
  }

  @Test
  void renameWithBlankLabelReturnsBadRequest() {
    HttpClientResponseException ex =
        org.junit.jupiter.api.Assertions.assertThrows(
            HttpClientResponseException.class,
            () ->
                client
                    .toBlocking()
                    .exchange(
                        HttpRequest.PATCH(
                                "/auth/admin/credentials/" + Base64Url.encode(new byte[] {4, 5, 6}),
                                "{\"label\":\"  \"}")
                            .bearerAuth(tokenFor("rename-blank-user"))
                            .contentType(MediaType.APPLICATION_JSON)));
    Assertions.assertThat(ex.getStatus().getCode()).isEqualTo(HttpStatus.BAD_REQUEST.getCode());
  }

  @Test
  void deleteUnknownCredentialReturnsNotFound() {
    HttpClientResponseException ex =
        org.junit.jupiter.api.Assertions.assertThrows(
            HttpClientResponseException.class,
            () ->
                client
                    .toBlocking()
                    .exchange(
                        HttpRequest.DELETE(
                                "/auth/admin/credentials/" + Base64Url.encode(new byte[] {7, 8, 9}))
                            .bearerAuth(tokenFor("delete-user"))));
    Assertions.assertThat(ex.getStatus().getCode()).isEqualTo(HttpStatus.NOT_FOUND.getCode());
  }
}
