// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

/**
 * Host-app extension point that maps a feature-specific {@code Context} into the wire-level message
 * payload {@code M} that pk-auth hands to its delivery SPIs ({@code EmailSender}, {@code
 * SmsSender}, etc.).
 *
 * <p>Feature services (magic-link, OTP, ...) ship a {@code Default*Formatter} that preserves the
 * original hard-coded copy. Host applications override this SPI to inject branded subject lines,
 * localised bodies, or templated HTML without forking the feature service itself.
 *
 * <p>Implementations must be deterministic, thread-safe, and side-effect-free; they are invoked
 * inside the service's send path, so any I/O (database lookups, remote template rendering) will
 * directly impact the latency of the send and the rate-limit semantics. Caching belongs inside the
 * implementation.
 *
 * @param <C> the feature-specific context type (e.g. {@code MagicLinkContext}, {@code OtpContext})
 *     carrying everything the formatter needs to render the message: user handle, recipient
 *     address, the generated link or code, and any per-flow metadata
 * @param <M> the feature-specific message type (e.g. {@code MagicLinkMessage}, {@code OtpMessage}),
 *     a small record consumed by the delivery SPI ({@code EmailSender.send}, {@code
 *     SmsSender.send})
 * @since 0.9.1
 */
@FunctionalInterface
public interface MessageFormatter<C, M> {

  /**
   * Renders {@code context} into a delivery-ready message.
   *
   * @param context feature-specific context; never {@code null}
   * @return the rendered message; must not be {@code null}
   * @since 0.9.1
   */
  M format(C context);
}
