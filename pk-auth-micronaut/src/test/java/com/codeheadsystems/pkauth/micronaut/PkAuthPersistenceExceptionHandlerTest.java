// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.codeheadsystems.pkauth.spi.PkAuthPersistenceException;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Maps {@link PkAuthPersistenceException} to a stable 503 JSON body. */
class PkAuthPersistenceExceptionHandlerTest {

  private final PkAuthPersistenceExceptionHandler handler = new PkAuthPersistenceExceptionHandler();

  @Test
  void mapsToServiceUnavailableWithOperationTag() {
    HttpResponse<?> response =
        handler.handle(
            mock(HttpRequest.class),
            new PkAuthPersistenceException("credentials.save", "db unreachable"));

    assertThat(response.getStatus().getCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE.getCode());
    @SuppressWarnings("unchecked")
    Map<String, String> body = (Map<String, String>) response.body();
    assertThat(body)
        .containsEntry("error", "persistence_failure")
        .containsEntry("operation", "credentials.save");
  }
}
