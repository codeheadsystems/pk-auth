// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.magiclink;

import com.codeheadsystems.pkauth.api.UserHandle;
import org.jspecify.annotations.Nullable;

/**
 * Render context handed to a {@link com.codeheadsystems.pkauth.spi.MessageFormatter} when {@link
 * MagicLinkService} is about to dispatch a magic-link email. The formatter returns a {@link
 * MagicLinkMessage} that is forwarded to the {@link EmailSender}.
 *
 * @param user the user the link is being sent to. May be {@code null} only for the privacy-safe
 *     "user-not-found" branch of the login flow (in which case the service does not actually invoke
 *     the formatter; the parameter is nullable for completeness, and real callers do not observe
 *     null).
 * @param email the recipient address. Always non-null in practice.
 * @param magicLinkUrl the fully-formed URL the user is expected to click; it already includes the
 *     issued JWT as a query parameter and is safe to embed verbatim in the body.
 * @param purpose either {@link MagicLinkService#PURPOSE_EMAIL_VERIFY} or {@link
 *     MagicLinkService#PURPOSE_LOGIN}. Formatters typically branch on this value to choose subject
 *     line and copy.
 * @since 0.9.1
 */
public record MagicLinkContext(
    @Nullable UserHandle user, String email, String magicLinkUrl, String purpose) {}
