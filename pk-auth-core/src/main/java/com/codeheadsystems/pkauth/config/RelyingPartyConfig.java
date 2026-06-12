// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.config;

import java.util.Collection;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.Nullable;

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

  /**
   * Builds a {@link RelyingPartyConfig} from raw host configuration, applying the validation and
   * the canonical "required — no defaults" error message every adapter shares. RP id, name, and
   * origins are mandatory (there is deliberately no default); a missing or blank value raises an
   * {@link IllegalStateException} naming the {@code pkauth.relying-party.*} configuration keys.
   *
   * @param id the RP ID (eTLD+1), or null/blank if unset.
   * @param name human-readable RP name, or null/blank if unset.
   * @param origins acceptable client-reported origins, or null/empty if unset; copied defensively.
   * @return the validated relying-party config.
   * @since 1.3.1
   */
  public static RelyingPartyConfig from(
      @Nullable String id, @Nullable String name, @Nullable Collection<String> origins) {
    if (id == null
        || id.isBlank()
        || name == null
        || name.isBlank()
        || origins == null
        || origins.isEmpty()) {
      throw new IllegalStateException(
          "pkauth.relying-party.{id,name,origins} are required. Set them explicitly in"
              + " configuration — there are no defaults.");
    }
    return new RelyingPartyConfig(id, name, Set.copyOf(origins));
  }
}
