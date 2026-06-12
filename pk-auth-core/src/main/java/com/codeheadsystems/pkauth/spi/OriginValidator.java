// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import java.util.Objects;

/**
 * Predicate over the client-reported origin. The default implementation is a strict allow-list
 * match against {@link RelyingPartyConfig#origins()}. Custom implementations may accept additional
 * origins (e.g., embedded webviews) — at their own risk.
 *
 * @since 0.9.0
 */
@FunctionalInterface
public interface OriginValidator {

  /**
   * Decides whether a client-reported WebAuthn origin is acceptable for this relying party.
   *
   * @param origin the origin string from the authenticator's client data (e.g. {@code
   *     https://example.com}).
   * @return {@code true} if the origin is allowed; {@code false} (including for a {@code null}
   *     origin) rejects the ceremony.
   * @since 0.9.0
   */
  boolean isAllowed(String origin);

  /** Strict allow-list validator backed by the configured set of origins. */
  static OriginValidator strict(RelyingPartyConfig config) {
    Objects.requireNonNull(config, "config");
    return origin -> origin != null && config.origins().contains(origin);
  }
}
