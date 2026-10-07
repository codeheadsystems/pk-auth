// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.otp;

/**
 * Rendered SMS payload produced by a {@link com.codeheadsystems.pkauth.spi.MessageFormatter} and
 * handed to {@link SmsSender#send(String, String)}.
 *
 * @param body the SMS body. Must be non-null and is sent verbatim; formatters are responsible for
 *     keeping it within carrier length limits.
 * @since 0.9.1
 */
public record OtpMessage(String body) {}
