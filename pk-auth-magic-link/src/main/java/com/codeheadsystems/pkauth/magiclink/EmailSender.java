// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.magiclink;

/**
 * SPI for sending an email containing a magic link. Per brief §3, pk-auth ships only the SPI plus a
 * logging dev sender and a JavaMail skeleton; production deployments wire a real provider.
 *
 * <p>The method is named {@code send} (rather than {@code sendMagicLink}) so the same SPI can be
 * reused by future email-bearing flows without renaming; see item #25 of the consolidated review.
 * Subject and body are produced upstream by a {@link
 * com.codeheadsystems.pkauth.spi.MessageFormatter}, so this SPI's only job is delivery.
 *
 * @since 0.9.1
 */
public interface EmailSender {

  /**
   * Sends {@code body} to {@code to} with the given {@code subject}.
   *
   * @param to recipient address; never {@code null}
   * @param subject email subject; never {@code null}
   * @param body email body; never {@code null}. Plaintext or HTML at the implementation's
   *     discretion.
   * @since 0.9.1
   */
  void send(String to, String subject, String body);
}
