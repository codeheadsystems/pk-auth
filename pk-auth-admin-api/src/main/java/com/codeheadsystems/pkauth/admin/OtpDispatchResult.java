// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import java.util.Objects;

/**
 * Returned from {@code POST /auth/admin/phone/start-verification}.
 *
 * @since 0.9.0
 */
public record OtpDispatchResult(String otpId) {
  public OtpDispatchResult {
    Objects.requireNonNull(otpId, "otpId");
  }
}
