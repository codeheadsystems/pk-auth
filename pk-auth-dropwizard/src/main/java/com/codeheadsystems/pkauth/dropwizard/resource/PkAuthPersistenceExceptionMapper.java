// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.resource;

import com.codeheadsystems.pkauth.spi.PkAuthPersistenceException;
import com.codeheadsystems.pkauth.spi.PkAuthPersistenceResponse;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Maps the SPI exception contract (see {@link
 * com.codeheadsystems.pkauth.spi.PkAuthPersistenceException}) to a stable {@code 503 Service
 * Unavailable} JSON response — same wire shape as the Spring and Micronaut adapters. Registered by
 * {@link com.codeheadsystems.pkauth.dropwizard.PkAuthBundle}.
 */
@Provider
public class PkAuthPersistenceExceptionMapper
    implements ExceptionMapper<PkAuthPersistenceException> {

  private static final Logger LOG = LoggerFactory.getLogger(PkAuthPersistenceExceptionMapper.class);

  @Override
  public Response toResponse(PkAuthPersistenceException exception) {
    LOG.warn(
        "pkauth.persistence.failure operation={} message={}",
        exception.operation(),
        exception.getMessage(),
        exception);
    return Response.status(PkAuthPersistenceResponse.STATUS)
        .entity(PkAuthPersistenceResponse.body(exception))
        .build();
  }
}
