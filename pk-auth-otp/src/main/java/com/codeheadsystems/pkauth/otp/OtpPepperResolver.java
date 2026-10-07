// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.otp;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Shared OTP-pepper resolution policy used by every adapter (Spring, Micronaut, Dropwizard).
 *
 * <p>The OTP service hashes inbound 6-digit codes with an HMAC keyed by a server-side pepper, a
 * Base64-encoded ≥ 16-byte secret. Without a stable pepper, OTPs minted before a restart cannot be
 * verified afterwards (and cannot be verified at all on a replica with a different pepper). This
 * resolver centralises the policy:
 *
 * <ul>
 *   <li>Configured pepper present → decode Base64 and require ≥ 16 decoded bytes (32+ recommended).
 *   <li>Unset and {@code devMode=true} → generate a per-startup random pepper and log a loud
 *       warning. Per-startup peppers invalidate outstanding OTPs across restarts and across cluster
 *       instances; dev only.
 *   <li>Unset and {@code devMode} false/unset → fail fast at startup.
 * </ul>
 *
 * <p>Adapters call {@link #resolve(Supplier, BooleanSupplier)} once during factory wiring and pass
 * the returned bytes to {@code OtpService.create(deps, pepper)} (or {@code
 * OtpService.Config.defaults(pepper)}).
 *
 * @since 0.9.1
 */
public final class OtpPepperResolver {

  private static final Logger LOG = LoggerFactory.getLogger(OtpPepperResolver.class);

  private OtpPepperResolver() {
    // utility class
  }

  /**
   * Resolves the OTP pepper bytes per the policy described in the class javadoc.
   *
   * @param configuredPepper supplier for the configured Base64 pepper value (may return {@code
   *     null} or blank when unset)
   * @param devMode supplier for the {@code pkauth.dev-mode} flag; only consulted when the pepper is
   *     unset, so adapters can defer reading the flag
   * @return at least 16 bytes of pepper material
   * @throws IllegalStateException when the configured pepper is invalid, or when no pepper is set
   *     and {@code devMode} is false
   * @since 0.9.1
   */
  public static byte[] resolve(Supplier<String> configuredPepper, BooleanSupplier devMode) {
    String configured = configuredPepper.get();
    if (configured != null && !configured.isBlank()) {
      byte[] decoded;
      try {
        decoded = Base64.getDecoder().decode(configured.trim());
      } catch (IllegalArgumentException e) {
        throw new IllegalStateException(
            "pkauth.otp.pepper must be a valid Base64 string (≥ 16 decoded bytes).", e);
      }
      if (decoded.length < 16) {
        throw new IllegalStateException(
            "pkauth.otp.pepper decoded to "
                + decoded.length
                + " bytes; at least 16 bytes required (32+ recommended).");
      }
      return decoded;
    }
    if (!devMode.getAsBoolean()) {
      throw new IllegalStateException(
          "pkauth.otp.pepper is not configured. Set a Base64-encoded ≥32-byte secret in"
              + " configuration, or enable pkauth.dev-mode=true to auto-generate a per-startup"
              + " random pepper (dev only — invalidates OTPs across restarts / cluster"
              + " instances).");
    }
    byte[] random = new byte[32];
    new SecureRandom().nextBytes(random);
    LOG.warn(
        "pkauth.dev-mode=true and pkauth.otp.pepper not set: generated a one-shot random OTP"
            + " pepper. Outstanding OTPs will not survive a restart and will not validate on"
            + " other instances. DO NOT use this configuration in production.");
    return random;
  }
}
