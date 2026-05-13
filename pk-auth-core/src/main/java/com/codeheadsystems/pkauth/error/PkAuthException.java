// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.error;

import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Base unchecked exception for pk-auth programmer errors. Ceremony-flow failures are returned as
 * variants of {@code *Result} sealed interfaces, not thrown.
 */
public abstract class PkAuthException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  private final PkAuthErrorCode errorCode;

  protected PkAuthException(PkAuthErrorCode errorCode, String message) {
    super(message);
    this.errorCode = Objects.requireNonNull(errorCode, "errorCode");
  }

  protected PkAuthException(PkAuthErrorCode errorCode, String message, @Nullable Throwable cause) {
    super(message, cause);
    this.errorCode = Objects.requireNonNull(errorCode, "errorCode");
  }

  public PkAuthErrorCode errorCode() {
    return errorCode;
  }
}
