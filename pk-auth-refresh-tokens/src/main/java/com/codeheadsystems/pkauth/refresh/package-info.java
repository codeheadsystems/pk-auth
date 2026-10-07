// SPDX-License-Identifier: MIT

/**
 * Rotating refresh tokens with family-based replay defence.
 *
 * <p>The {@link com.codeheadsystems.pkauth.refresh.RefreshTokenService} is the public entry point:
 * issue a token for a user, rotate it on every refresh, revoke a family on logout, or revoke every
 * family for a user on account compromise. Each rotation produces a child token in the same family
 * with a link to the parent; replaying any used or revoked token in a family scorches the entire
 * family ({@link com.codeheadsystems.pkauth.refresh.RotateResult.Replayed}). See ADR 0013.
 *
 * <p>Wire format is {@code "{refreshId}.{secret}"} where both halves are base64url; only the
 * SHA-256 hash of the secret is persisted. The {@link
 * com.codeheadsystems.pkauth.refresh.spi.RefreshTokenRepository} SPI declares the atomic mark-used
 * contract that backs the replay defence; it is a single conditional UPDATE / DynamoDB conditional
 * write that succeeds iff the token is fresh.
 *
 * <p>The service does not call {@link com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer} on its own.
 * It returns the data the consumer needs to mint a fresh access token, keeping the two primitives
 * composable.
 *
 * @since 1.1.0
 */
package com.codeheadsystems.pkauth.refresh;
