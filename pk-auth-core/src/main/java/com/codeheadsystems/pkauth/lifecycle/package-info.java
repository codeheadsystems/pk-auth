// SPDX-License-Identifier: MIT

/**
 * User-lifecycle fan-out. {@link com.codeheadsystems.pkauth.lifecycle.UserDeletionService} runs
 * every registered {@link com.codeheadsystems.pkauth.lifecycle.UserDeletionListener} when a user is
 * removed, so the host gets a single call to revoke every credential category pk-auth manages
 * (passkeys, backup codes, OTPs, magic-link state, refresh tokens, access tokens). See ADR 0016 for
 * the design rationale.
 *
 * @since 1.1.0
 */
@org.jspecify.annotations.NullMarked
package com.codeheadsystems.pkauth.lifecycle;
