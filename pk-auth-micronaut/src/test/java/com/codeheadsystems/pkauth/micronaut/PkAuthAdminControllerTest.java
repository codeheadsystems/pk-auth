// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import com.codeheadsystems.pkauth.admin.AdminResult;
import io.micronaut.context.annotation.Property;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import java.time.Duration;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

/** Smoke tests for the admin controller and the {@link AdminResult} → HTTP mapping. */
@MicronautTest
@Property(name = "pkauth.relying-party.id", value = "example.com")
@Property(name = "pkauth.relying-party.name", value = "test")
@Property(name = "pkauth.relying-party.origins[0]", value = "https://example.com")
@Property(name = "pkauth.jwt.issuer", value = "https://pkauth.example.com")
@Property(name = "pkauth.jwt.audience", value = "https://app.example.com")
@Property(name = "pkauth.jwt.secret", value = "pk-auth-micronaut-test-secret-32b!")
@Property(name = "pkauth.dev-mode", value = "true")
class PkAuthAdminControllerTest {

  @Inject
  @Client("/")
  HttpClient client;

  @Test
  void adminAccountUnauthenticatedReturns401() {
    HttpClientResponseException ex =
        org.junit.jupiter.api.Assertions.assertThrows(
            HttpClientResponseException.class,
            () -> client.toBlocking().exchange(HttpRequest.GET("/auth/admin/account")));
    Assertions.assertThat(ex.getStatus().getCode()).isEqualTo(HttpStatus.UNAUTHORIZED.getCode());
  }

  @Test
  void adminCompleteEmailVerificationIsUnauthenticatedAndValidatesToken() {
    HttpClientResponseException ex =
        org.junit.jupiter.api.Assertions.assertThrows(
            HttpClientResponseException.class,
            () ->
                client
                    .toBlocking()
                    .exchange(
                        HttpRequest.POST(
                                "/auth/admin/email/complete-verification",
                                "{\"token\":\"not.a.jwt\"}")
                            .contentType(MediaType.APPLICATION_JSON)));
    Assertions.assertThat(ex.getStatus().getCode()).isEqualTo(HttpStatus.BAD_REQUEST.getCode());
  }

  @Test
  void adminResultMapperCoversEveryVariant() {
    Assertions.assertThat(PkAuthAdminController.toMicronaut(new AdminResult.Success<>("ok")).code())
        .isEqualTo(HttpStatus.OK.getCode());
    Assertions.assertThat(PkAuthAdminController.toMicronaut(new AdminResult.NotFound<>()).code())
        .isEqualTo(HttpStatus.NOT_FOUND.getCode());
    Assertions.assertThat(PkAuthAdminController.toMicronaut(new AdminResult.Forbidden<>()).code())
        .isEqualTo(HttpStatus.FORBIDDEN.getCode());
    Assertions.assertThat(
            PkAuthAdminController.toMicronaut(new AdminResult.ValidationFailed<>("x")).code())
        .isEqualTo(HttpStatus.BAD_REQUEST.getCode());
    Assertions.assertThat(PkAuthAdminController.toMicronaut(new AdminResult.Conflict<>("y")).code())
        .isEqualTo(HttpStatus.CONFLICT.getCode());
    Assertions.assertThat(
            PkAuthAdminController.toMicronaut(new AdminResult.RateLimited<>(Duration.ofMinutes(1)))
                .code())
        .isEqualTo(HttpStatus.TOO_MANY_REQUESTS.getCode());
  }
}
