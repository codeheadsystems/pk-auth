// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.otp;

import java.util.Objects;

/**
 * Intentional starter scaffold for the Twilio {@link SmsSender}. Per brief §3, pk-auth ships only
 * the SPI — host applications add the Twilio SDK dependency and replace {@link #send} with the real
 * REST call. The class ships in this form on purpose: it captures the canonical Twilio constructor
 * shape (account SID, auth token, sender number) and fails loudly if it is ever invoked unmodified.
 *
 * <p>This is <b>not</b> a half-finished feature. Do not remove it during dead-code sweeps; it is
 * one of the two SDK-naming anchors (alongside {@code JavaMailEmailSender}) that documents which
 * external libraries the project expects hosts to bring.
 *
 * @since 0.9.1
 */
public final class TwilioSmsSender implements SmsSender {

  // Retained to document the canonical Twilio constructor shape (account SID, auth token, sender
  // number) — the whole point of this naming-anchor skeleton. A real implementation reads them in
  // send(); until then they are intentionally unread and MUST NOT be echoed into logs/exceptions.
  @SuppressWarnings("unused")
  private final String accountSid;

  @SuppressWarnings("unused")
  private final String authToken;

  @SuppressWarnings("unused")
  private final String fromNumber;

  public TwilioSmsSender(String accountSid, String authToken, String fromNumber) {
    this.accountSid = Objects.requireNonNull(accountSid, "accountSid");
    this.authToken = Objects.requireNonNull(authToken, "authToken");
    this.fromNumber = Objects.requireNonNull(fromNumber, "fromNumber");
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.1
   */
  @Override
  public void send(String phoneE164, String body) {
    // Deliberately fail loud, but DO NOT echo credential material (account SID, sender number,
    // auth-token length) into the exception message — it would land in logs / stack traces if a
    // host ever wired this skeleton unmodified.
    throw new UnsupportedOperationException(
        "TwilioSmsSender is a skeleton; host applications must add the Twilio SDK dependency and"
            + " replace send() with the real REST call before sending SMS.");
  }
}
