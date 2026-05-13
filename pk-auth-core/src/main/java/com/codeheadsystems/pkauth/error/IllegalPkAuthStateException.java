// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.error;

import org.jspecify.annotations.Nullable;

/** Thrown when pk-auth state is used in a way that should be impossible — i.e. programmer error. */
public class IllegalPkAuthStateException extends PkAuthException {

  private static final long serialVersionUID = 1L;

  public IllegalPkAuthStateException(String message) {
    super(PkAuthErrorCode.ILLEGAL_STATE, message);
  }

  public IllegalPkAuthStateException(String message, @Nullable Throwable cause) {
    super(PkAuthErrorCode.ILLEGAL_STATE, message, cause);
  }
}
