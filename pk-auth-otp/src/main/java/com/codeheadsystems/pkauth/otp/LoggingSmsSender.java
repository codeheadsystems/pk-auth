// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.otp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Development-only {@link SmsSender} that logs the message instead of delivering an SMS.
 *
 * @since 0.9.1
 */
public final class LoggingSmsSender implements SmsSender {

  private static final Logger LOG = LoggerFactory.getLogger(LoggingSmsSender.class);

  public LoggingSmsSender() {}

  /**
   * {@inheritDoc}
   *
   * @since 0.9.1
   */
  @Override
  public void send(String phoneE164, String body) {
    // Do not log the message body — it contains the plaintext OTP code.
    LOG.info("sms.dev phone={} messageLength={}", OtpService.maskPhone(phoneE164), body.length());
  }
}
