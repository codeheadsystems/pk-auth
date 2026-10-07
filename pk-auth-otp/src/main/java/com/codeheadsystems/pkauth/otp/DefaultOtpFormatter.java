// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.otp;

import com.codeheadsystems.pkauth.spi.MessageFormatter;

/**
 * Default {@link MessageFormatter} for OTP SMS messages. Preserves the original hard-coded body
 * ({@code "Your verification code is XXXXXX"}) that {@link OtpService} used before the {@code
 * MessageFormatter} SPI was introduced (item #25 of the consolidated review). Host applications
 * inject their own {@code MessageFormatter<OtpContext, OtpMessage>} bean to brand or localise the
 * SMS body.
 *
 * @since 0.9.1
 */
public final class DefaultOtpFormatter implements MessageFormatter<OtpContext, OtpMessage> {

  /** {@inheritDoc} */
  @Override
  public OtpMessage format(OtpContext context) {
    return new OtpMessage("Your verification code is " + context.code());
  }
}
