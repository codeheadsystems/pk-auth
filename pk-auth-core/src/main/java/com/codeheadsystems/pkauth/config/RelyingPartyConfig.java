// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.config;

import java.util.Objects;
import java.util.Set;

/**
 * Relying-party identity used when issuing WebAuthn options.
 *
 * @param id the RP ID (eTLD+1, e.g. {@code "example.com"})
 * @param name human-readable RP name shown to the user during ceremonies
 * @param origins the set of acceptable client-reported origins ({@code https://example.com}, …)
 * @since 0.9.0
 */
public record RelyingPartyConfig(String id, String name, Set<String> origins) {

  public RelyingPartyConfig {
    Objects.requireNonNull(id, "id");
    if (id.isBlank()) {
      throw new IllegalArgumentException("RP id must be non-blank");
    }
    Objects.requireNonNull(name, "name");
    if (name.isBlank()) {
      throw new IllegalArgumentException("RP name must be non-blank");
    }
    Objects.requireNonNull(origins, "origins");
    if (origins.isEmpty()) {
      throw new IllegalArgumentException("origins must contain at least one entry");
    }
    origins = Set.copyOf(origins);
  }
}
