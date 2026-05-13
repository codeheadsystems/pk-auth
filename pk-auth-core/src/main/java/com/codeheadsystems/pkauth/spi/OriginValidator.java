// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import java.util.Objects;

/**
 * Predicate over the client-reported origin. The default implementation is a strict allow-list
 * match against {@link RelyingPartyConfig#origins()}. Custom implementations may accept additional
 * origins (e.g., embedded webviews) — at their own risk.
 */
@FunctionalInterface
public interface OriginValidator {

  boolean isAllowed(String origin);

  /** Strict allow-list validator backed by the configured set of origins. */
  static OriginValidator strict(RelyingPartyConfig config) {
    Objects.requireNonNull(config, "config");
    return origin -> origin != null && config.origins().contains(origin);
  }
}
