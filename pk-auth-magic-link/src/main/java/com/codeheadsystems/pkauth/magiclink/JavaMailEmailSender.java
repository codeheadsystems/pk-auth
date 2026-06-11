// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.magiclink;

import java.util.Objects;

/**
 * Intentional starter scaffold for the Jakarta Mail (JavaMail) {@link EmailSender}. Per brief §3,
 * pk-auth ships only the SPI — host applications add the Jakarta Mail dependency and replace {@link
 * #send} with the real SMTP transport. The class ships in this form on purpose: it captures the
 * canonical SMTP constructor shape (host, port, From address) and fails loudly if it is ever
 * invoked unmodified.
 *
 * <p>This is <b>not</b> a half-finished feature. Do not remove it during dead-code sweeps; it is
 * one of the two SDK-naming anchors (alongside {@code TwilioSmsSender}) that documents which
 * external libraries the project expects hosts to bring.
 *
 * @since 0.9.1
 */
public final class JavaMailEmailSender implements EmailSender {

  private final String smtpHost;
  private final int smtpPort;
  private final String fromAddress;

  public JavaMailEmailSender(String smtpHost, int smtpPort, String fromAddress) {
    this.smtpHost = Objects.requireNonNull(smtpHost, "smtpHost");
    this.smtpPort = smtpPort;
    this.fromAddress = Objects.requireNonNull(fromAddress, "fromAddress");
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.1
   */
  @Override
  public void send(String to, String subject, String body) {
    throw new UnsupportedOperationException(
        "JavaMailEmailSender is a skeleton; host applications must wire Jakarta Mail. host="
            + smtpHost
            + " port="
            + smtpPort
            + " from="
            + fromAddress
            + " to="
            + to
            + " subjectLength="
            + subject.length()
            + " bodyLength="
            + body.length());
  }
}
