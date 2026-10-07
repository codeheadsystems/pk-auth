// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.magiclink;

/**
 * Rendered email payload produced by a {@link com.codeheadsystems.pkauth.spi.MessageFormatter} and
 * handed to {@link EmailSender#send(String, String, String)}.
 *
 * @param subject the subject line. Must be non-null.
 * @param body the body text. Must be non-null; may be plaintext or HTML; the choice is the
 *     formatter's, and the {@link EmailSender} implementation is expected to honour it.
 * @since 0.9.1
 */
public record MagicLinkMessage(String subject, String body) {}
