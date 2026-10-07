// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.util.Objects;

/**
 * Wire-shape response for {@code POST /auth/admin/email/complete-verification}: JSON {@code
 * {"userHandle": "<base64url>"}}. Promoted out of the per-adapter controllers so every adapter
 * emits the identical envelope; before promotion the Spring adapter wrapped the handle in {@code
 * Map.of(...)} while Dropwizard and Micronaut returned the bare {@code UserHandle} value (which
 * serialises to a string but with no enclosing object).
 *
 * <p>The {@code userHandle} component is the type-safe {@link UserHandle} value class (was raw
 * {@code String} until 0.9.1's byte-array-removal sweep). Wire JSON is unchanged because {@link
 * UserHandle} has a registered Jackson serialiser that emits a base64url-encoded (RFC 4648 §5, no
 * padding) string of the handle bytes; this is the same shape adapters previously hand-stitched
 * with {@code Base64Url.encode(handle.value())}.
 *
 * @param userHandle the verified user's handle (serialises as base64url string on the wire)
 * @since 0.9.1
 */
public record EmailVerificationResult(UserHandle userHandle) {

  /** Defensive null-check: the wire field must always be present. */
  public EmailVerificationResult {
    Objects.requireNonNull(userHandle, "userHandle");
  }
}
