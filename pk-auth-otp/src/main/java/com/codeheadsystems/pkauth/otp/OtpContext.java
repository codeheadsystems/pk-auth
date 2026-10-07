// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.otp;

import com.codeheadsystems.pkauth.api.UserHandle;

/**
 * Render context handed to a {@link com.codeheadsystems.pkauth.spi.MessageFormatter} when {@link
 * OtpService} is about to dispatch an SMS containing a one-time code. The formatter returns an
 * {@link OtpMessage} that is forwarded to the {@link SmsSender}.
 *
 * @param user the user receiving the code; never {@code null}.
 * @param phoneE164 the destination phone number in E.164 format; never {@code null}.
 * @param code the freshly generated 6-digit OTP, as plaintext digits. Formatters must embed this
 *     verbatim in the rendered SMS body; the user types it back to complete verification.
 * @since 0.9.1
 */
public record OtpContext(UserHandle user, String phoneE164, String code) {}
