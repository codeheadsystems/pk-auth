// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.error;

import org.jspecify.annotations.Nullable;

/** Thrown when pk-auth is misconfigured (missing RP id, no origins, etc.). */
public class ConfigurationException extends PkAuthException {

  private static final long serialVersionUID = 1L;

  public ConfigurationException(String message) {
    super(PkAuthErrorCode.CONFIGURATION, message);
  }

  public ConfigurationException(String message, @Nullable Throwable cause) {
    super(PkAuthErrorCode.CONFIGURATION, message, cause);
  }
}
