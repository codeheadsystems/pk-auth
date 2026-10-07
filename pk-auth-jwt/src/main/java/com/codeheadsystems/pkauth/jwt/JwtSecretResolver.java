// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import java.nio.charset.StandardCharsets;

/**
 * Shared JWT-secret resolution policy for every adapter (Spring, Micronaut, Dropwizard).
 *
 * <p>pk-auth's HS256 JWT issuer/validator need a stable signing key. A randomly generated
 * per-startup key is unsafe: it breaks multi-instance deployments, invalidates outstanding tokens
 * across restarts, and silently masks misconfiguration. This resolver enforces a fail-fast policy:
 *
 * <ul>
 *   <li>Configured secret present → require ≥ 32 bytes when interpreted as UTF-8.
 *   <li>Configured secret missing or blank → throw {@link IllegalStateException} with a clear
 *       remediation message. Hosts that want their own key material (e.g. ES256) supply a {@link
 *       JwtKeyset} bean themselves.
 * </ul>
 *
 * <p>Adapters call {@link #resolveHs256Bytes(String)} once during factory wiring and pass the
 * result to {@link JwtKeyset#hs256(byte[])}.
 *
 * @since 0.9.1
 */
public final class JwtSecretResolver {

  private JwtSecretResolver() {
    // utility class
  }

  /**
   * Validates the configured shared secret and returns its UTF-8 bytes.
   *
   * @param configured the raw value of {@code pkauth.jwt.secret} (may be {@code null} or blank)
   * @return the secret encoded as UTF-8 bytes (≥ 32 bytes)
   * @throws IllegalStateException when the secret is missing, blank, or shorter than 32 bytes
   * @since 0.9.1
   */
  public static byte[] resolveHs256Bytes(String configured) {
    if (configured == null || configured.isBlank()) {
      throw new IllegalStateException(
          "pkauth.jwt.secret must be configured (≥ 32 bytes for HS256), or supply a JwtKeyset"
              + " bean. Silent fallback to a random one-shot key was removed because it breaks"
              + " multi-instance deployments and masks misconfiguration.");
    }
    byte[] bytes = configured.getBytes(StandardCharsets.UTF_8);
    if (bytes.length < 32) {
      throw new IllegalStateException(
          "pkauth.jwt.secret must be at least 32 bytes for HS256 (got "
              + bytes.length
              + "). Configure a ≥ 32-byte random value or supply a JwtKeyset bean.");
    }
    return bytes;
  }

  /**
   * Convenience wrapper that returns a fully-built {@link JwtKeyset} from the configured secret.
   *
   * @param configured the raw value of {@code pkauth.jwt.secret} (may be {@code null} or blank)
   * @return a single-key HS256 keyset
   * @throws IllegalStateException when the secret is missing, blank, or shorter than 32 bytes
   * @since 0.9.1
   */
  public static JwtKeyset resolveHs256Keyset(String configured) {
    return JwtKeyset.hs256(resolveHs256Bytes(configured));
  }
}
