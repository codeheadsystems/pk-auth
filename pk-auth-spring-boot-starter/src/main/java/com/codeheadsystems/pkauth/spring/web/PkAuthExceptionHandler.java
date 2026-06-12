// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.web;

import com.codeheadsystems.pkauth.spi.PkAuthPersistenceException;
import com.codeheadsystems.pkauth.spi.PkAuthPersistenceResponse;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Maps the SPI exception contract (see {@link
 * com.codeheadsystems.pkauth.spi.PkAuthPersistenceException}) to a stable {@code 503 Service
 * Unavailable} response with a {@code {"error": "persistence_failure", "operation": "..."}} body —
 * the same envelope used by the admin and ceremony error responses. This means a host-side DB
 * outage surfaces consistently to the {@code @pk-auth/passkeys-browser} SDK instead of leaking
 * framework-default 500 HTML.
 */
@RestControllerAdvice(basePackages = "com.codeheadsystems.pkauth.spring")
public class PkAuthExceptionHandler {

  private static final Logger LOG = LoggerFactory.getLogger(PkAuthExceptionHandler.class);

  @ExceptionHandler(PkAuthPersistenceException.class)
  public ResponseEntity<Map<String, String>> handlePersistence(PkAuthPersistenceException e) {
    LOG.warn(
        "pkauth.persistence.failure operation={} message={}", e.operation(), e.getMessage(), e);
    return ResponseEntity.status(PkAuthPersistenceResponse.STATUS)
        .body(PkAuthPersistenceResponse.body(e));
  }
}
