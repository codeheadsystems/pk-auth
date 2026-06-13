// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Shared producer for the stable wire envelope every adapter returns when a {@link
 * PkAuthPersistenceException} escapes an SPI call: HTTP {@value #STATUS} with a {@code
 * {"error":"persistence_failure","operation":"..."}} body.
 *
 * <p>Centralizing the status and body here keeps the three adapters' exception handlers from
 * drifting and guarantees a host-side DB outage surfaces as the same sanitized {@code 503} from
 * every adapter, instead of one accidentally leaking a framework-default 500 with a stack trace.
 * Each adapter keeps only its framework-specific glue (response type, logging).
 *
 * @since 2.0.0
 */
public final class PkAuthPersistenceResponse {

  /** HTTP status returned for a persistence failure: {@code 503 Service Unavailable}. */
  public static final int STATUS = 503;

  /** Stable machine-readable error code carried in the response body. */
  public static final String ERROR_CODE = "persistence_failure";

  private PkAuthPersistenceResponse() {}

  /**
   * Builds the neutral response body for {@code exception}. Adapters wrap this map in their own
   * framework response type at {@link #STATUS}.
   *
   * @param exception the persistence failure to render.
   * @return an insertion-ordered map with {@code error} and {@code operation} keys.
   * @since 2.0.0
   */
  public static Map<String, String> body(PkAuthPersistenceException exception) {
    Map<String, String> body = new LinkedHashMap<>();
    body.put("error", ERROR_CODE);
    body.put("operation", exception.operation());
    return body;
  }
}
