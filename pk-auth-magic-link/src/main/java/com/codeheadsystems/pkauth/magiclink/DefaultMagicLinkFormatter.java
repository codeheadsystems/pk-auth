// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.magiclink;

import com.codeheadsystems.pkauth.spi.MessageFormatter;

/**
 * Default {@link MessageFormatter} for magic-link emails. Preserves the original hard-coded subject
 * and body strings that {@link MagicLinkService} used before the {@code MessageFormatter} SPI was
 * introduced (item #25 of the consolidated review). Host applications that need branding,
 * localisation, or HTML bodies inject their own {@code MessageFormatter<MagicLinkContext,
 * MagicLinkMessage>} bean instead.
 *
 * @since 0.9.1
 */
public final class DefaultMagicLinkFormatter
    implements MessageFormatter<MagicLinkContext, MagicLinkMessage> {

  /** {@inheritDoc} */
  @Override
  public MagicLinkMessage format(MagicLinkContext context) {
    if (MagicLinkService.PURPOSE_LOGIN.equals(context.purpose())) {
      return new MagicLinkMessage("Sign in", "Click to sign in: " + context.magicLinkUrl());
    }
    // Default branch covers PURPOSE_EMAIL_VERIFY and any future purpose values.
    return new MagicLinkMessage("Verify your email", "Click to verify: " + context.magicLinkUrl());
  }
}
