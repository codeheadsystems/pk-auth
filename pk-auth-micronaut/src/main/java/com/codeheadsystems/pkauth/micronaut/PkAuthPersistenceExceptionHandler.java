// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import com.codeheadsystems.pkauth.spi.PkAuthPersistenceException;
import com.codeheadsystems.pkauth.spi.PkAuthPersistenceResponse;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.server.exceptions.ExceptionHandler;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Maps the SPI exception contract (see {@link
 * com.codeheadsystems.pkauth.spi.PkAuthPersistenceException}) to a stable {@code 503 Service
 * Unavailable} JSON response — same wire shape as the Spring and Dropwizard adapters.
 */
@Produces
@Singleton
@Requires(classes = {PkAuthPersistenceException.class, ExceptionHandler.class})
public class PkAuthPersistenceExceptionHandler
    implements ExceptionHandler<PkAuthPersistenceException, HttpResponse<?>> {

  private static final Logger LOG =
      LoggerFactory.getLogger(PkAuthPersistenceExceptionHandler.class);

  @Override
  @SuppressWarnings(
      "rawtypes") // Micronaut's ExceptionHandler#handle signature uses a raw HttpRequest.
  public HttpResponse<?> handle(HttpRequest request, PkAuthPersistenceException exception) {
    LOG.warn(
        "pkauth.persistence.failure operation={} message={}",
        exception.operation(),
        exception.getMessage(),
        exception);
    return HttpResponse.status(HttpStatus.valueOf(PkAuthPersistenceResponse.STATUS))
        .body(PkAuthPersistenceResponse.body(exception));
  }
}
