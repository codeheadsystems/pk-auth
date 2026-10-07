// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Data the consumer needs to mint a fresh access token after a successful refresh-token rotation.
 * Returned inside {@link RotateResult.Success} so the caller (typically the refresh HTTP endpoint)
 * can hand the values to {@link com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer}; {@link
 * com.codeheadsystems.pkauth.refresh.RefreshTokenService} does not call the issuer itself, which
 * keeps the two primitives composable.
 *
 * @param userHandle owning user (from the rotated token's row)
 * @param audience audience the new access token should be scoped to (same as the rotated token's)
 * @param deviceId optional device identifier carried through the rotation chain
 * @param amr RFC 8176 authentication method references from the original authentication, carried
 *     through the rotation chain so the refreshed access token reflects the original method rather
 *     than a generic value. Added in 1.3.0.
 * @since 1.1.0
 */
public record RotatedClaims(
    UserHandle userHandle, String audience, Optional<String> deviceId, List<String> amr) {

  public RotatedClaims {
    Objects.requireNonNull(userHandle, "userHandle");
    Objects.requireNonNull(audience, "audience");
    Objects.requireNonNull(deviceId, "deviceId");
    Objects.requireNonNull(amr, "amr");
    if (amr.isEmpty()) {
      throw new IllegalArgumentException("amr must be non-empty");
    }
    amr = List.copyOf(amr);
  }
}
