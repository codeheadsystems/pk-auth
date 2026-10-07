// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.otp;

/**
 * SPI for sending an SMS containing an OTP. Implementations live in adapter modules / host
 * applications. The brief ships only a {@link LoggingSmsSender} for dev and a skeleton {@link
 * TwilioSmsSender}.
 *
 * <p>The method is named {@code send} (rather than {@code sendOtp}) so the same SPI can be reused
 * by future SMS-bearing flows without renaming; see item #25 of the consolidated review. The body
 * is produced upstream by a {@link com.codeheadsystems.pkauth.spi.MessageFormatter}, so this SPI's
 * only job is delivery.
 *
 * @since 0.9.1
 */
public interface SmsSender {

  /**
   * Sends {@code body} to the given {@code phoneE164} number.
   *
   * @param phoneE164 recipient number in E.164 format; never {@code null}
   * @param body SMS body; never {@code null} and assumed to fit carrier length limits
   * @since 0.9.1
   */
  void send(String phoneE164, String body);
}
