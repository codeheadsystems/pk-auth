// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.time.Instant;
import java.util.Optional;

/**
 * SPI for persisting issued JWT JTIs ("stateful access tokens"). Hosts bind a real implementation
 * when they need server-side revocation of access tokens, for example an immediate logout that
 * rejects the bearer's still-unexpired JWT, or a "log out everywhere" admin action.
 *
 * <p>{@link PkAuthJwtIssuer#issue(JwtClaims)} calls {@link #record record} for every issued token;
 * {@link PkAuthJwtValidator#validate(String)} calls {@link #exists exists} after signature and
 * claim checks. A return of {@code false} from {@code exists} yields {@link
 * JwtVerificationResult.Revoked}. The default {@link #noop()} implementation accepts every JTI and
 * persists nothing, preserving stateless-JWT behaviour for hosts that want it.
 *
 * <p>Contrast with {@link RevocationCheck}: that SPI is a fast deny-list ("is this jti blocked?").
 * {@code AccessTokenStore} is the inverse: a positive allow-list ("was this jti issued, and has it
 * not been deleted?"). The two coexist:
 *
 * <ul>
 *   <li>Stateless mode: no store bound (i.e. {@link #noop()} active). Tokens are valid until {@code
 *       exp}. Hosts that want lightweight invalidation use {@link RevocationCheck} to consult a
 *       small in-memory deny-list of revoked jtis.
 *   <li>Stateful mode: a real store is bound. Every issued token has a row; deleting the row (e.g.
 *       on logout) immediately invalidates the bearer.
 * </ul>
 *
 * <p>Implementations must be safe to call from many threads concurrently. Failures from {@link
 * #record} must propagate so issuance fails; partial state is unacceptable. See ADR 0015.
 *
 * @since 1.1.0
 */
public interface AccessTokenStore {

  /**
   * Persists a freshly-issued token. Called by {@link PkAuthJwtIssuer#issue(JwtClaims)} after the
   * JWT has been signed and before the wire token is returned to the caller. If this method throws,
   * the issuer propagates the exception and no token is returned.
   *
   * @param jti the JWT id claim (unique per issued token; {@link PkAuthJwtIssuer} generates a
   *     random UUID)
   * @param userHandle owning user
   * @param audience the {@code aud} claim of the issued token (post per-audience-TTL dispatch)
   * @param deviceId optional device identifier for hosts that bind tokens to physical devices
   * @param issuedAt the {@code iat} value
   * @param expiresAt the {@code exp} value; implementations may use this to prune rows whose access
   *     window has elapsed
   */
  void record(
      String jti,
      UserHandle userHandle,
      String audience,
      Optional<String> deviceId,
      Instant issuedAt,
      Instant expiresAt);

  /**
   * Returns {@code true} iff a row for the given {@code jti} exists in the store. Called by {@link
   * PkAuthJwtValidator#validate(String)} after signature, issuer, audience, and skew checks have
   * passed.
   *
   * <p>The {@link #noop()} implementation returns {@code true} unconditionally so stateless
   * deployments behave as if no store were involved.
   *
   * <p>Fail closed on outage: if the backing store is unreachable, implementations throw rather
   * than return {@code true}: a thrown exception propagates out of {@link
   * PkAuthJwtValidator#validate(String)} so the host's filter rejects the request (no token
   * accepted), whereas returning {@code true} would fail open and accept a possibly-revoked token
   * during the outage. Host integrations must therefore treat a thrown {@code validate(...)} as an
   * authentication failure, not swallow it into success.
   */
  boolean exists(String jti);

  /**
   * Removes the row for the given {@code jti}, but only if it is owned by {@code userHandle}.
   * Idempotent. Returns {@code true} iff a row was deleted; an ownership mismatch returns {@code
   * false} (silent, with the same shape as "not found", so callers cannot use this to probe for jti
   * existence across users). The {@code userHandle} scope is defence in depth on top of the
   * service-layer ownership check: even with a 122-bit random JTI making cross-user collision
   * implausible, requiring the owner on the predicate ensures a future caller forwarding a
   * client-supplied jti without an ownership check cannot escalate into IDOR.
   */
  boolean delete(UserHandle userHandle, String jti);

  /**
   * Removes every row for the supplied user. Called by {@link
   * com.codeheadsystems.pkauth.lifecycle.UserDeletionService} during user-deletion fan-out.
   *
   * @return how many rows were deleted (best-effort; useful for structured logging)
   */
  int deleteAllForUser(UserHandle userHandle);

  /**
   * Operator cleanup hook: removes rows whose {@code expires_at} is strictly less than {@code
   * before}. Stateful access tokens have a natural pruning window: once {@code exp} has passed, the
   * bearer is rejected on the {@code exp} check anyway, so the row is no longer load-bearing. Hosts
   * schedule this as a periodic job; see {@code docs/operator-guide.md}.
   */
  int deleteExpiredBefore(Instant before);

  /**
   * Returns a no-op store: {@link #record} discards, {@link #exists} returns {@code true} for every
   * jti, and the delete/cleanup methods all return zero. This is the default binding when the host
   * has not supplied a real implementation; issuance and validation behave as if no server-side
   * state existed.
   */
  static AccessTokenStore noop() {
    return NoopAccessTokenStore.INSTANCE;
  }
}
