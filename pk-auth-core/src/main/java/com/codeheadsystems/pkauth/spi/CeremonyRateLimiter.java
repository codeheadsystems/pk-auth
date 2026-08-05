// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import org.jspecify.annotations.Nullable;

/**
 * Host-app integration point that throttles WebAuthn ceremony endpoints ({@code
 * /auth/passkeys/registration/start}, {@code .../registration/finish}, {@code
 * .../authentication/start}, {@code .../authentication/finish}) per source IP and per username.
 * Without this throttle, the public {@code start*} / {@code finish*} endpoints enable account
 * enumeration (combined with the {@code allowCredentials} / {@code excludeCredentials} shape),
 * challenge spam (each {@code start*} writes to {@link ChallengeStore}), and brute-force assertion
 * probes against {@code finishAuthentication}.
 *
 * <p>Contract: each {@code tryAcquire*} method returns {@code true} when the call is allowed and
 * {@code false} when the configured limit for the bucket has been exhausted within the limiter's
 * window. Implementations MUST be race-safe — concurrent calls observing the same bucket near its
 * limit must converge to at most {@code limit} {@code true} returns per window.
 *
 * <p>The ceremony service consults the limiter exactly once per public entrypoint:
 *
 * <ul>
 *   <li>{@code startRegistration} / {@code startAuthentication} — IP bucket only when the request
 *       carries no username; IP + username buckets when a username is supplied.
 *   <li>{@code finishRegistration} / {@code finishAuthentication} — IP bucket only (these endpoints
 *       do not carry a username on the wire; binding is via the {@code challengeId}).
 * </ul>
 *
 * <p>When the limiter denies a call, the ceremony service short-circuits before generating /
 * consulting a challenge and surfaces the refusal through sealed result types: {@code
 * AssertionResult.RateLimited} / {@code RegistrationResult.RateLimited} for {@code finish*}, and
 * {@code StartAuthenticationResult.RateLimited} / {@code StartRegistrationResult.RateLimited} for
 * {@code start*}.
 *
 * <p><strong>Production deployments with more than one replica MUST override this SPI with a
 * shared, race-safe limiter (Redis token-bucket, etc.). The default implementation supplied by
 * pk-auth ({@code InMemoryCeremonyRateLimiter}) tracks counters in a per-process Caffeine cache and
 * is for single-instance or dev use only;</strong> per-replica counters multiply by the cluster
 * size. This SPI mirrors the {@code MagicLinkRateLimiter} pattern: pk-auth ships a Caffeine-backed
 * default suitable for dev / single-node deployments, and emits a startup WARN when the in-memory
 * default is wired so operators notice before a production rollout.
 *
 * @since 0.9.1
 */
public interface CeremonyRateLimiter {

  /**
   * Returns whether a ceremony call from {@code ip} is allowed under the current per-IP budget.
   *
   * @param ip the source IP address (may be {@code null} if the host cannot determine it — in that
   *     case implementations SHOULD fall back to a single shared bucket or treat as {@code true})
   * @return {@code true} when allowed; {@code false} when the per-IP budget for the current window
   *     is exhausted
   * @since 0.9.1
   */
  boolean tryAcquireForIp(@Nullable String ip);

  /**
   * Returns whether a ceremony call for {@code username} is allowed under the current per-username
   * budget. Only called by the ceremony service for {@code start*} requests that carry a username;
   * {@code finish*} requests have no username on the wire and consult only the per-IP bucket.
   *
   * <p><strong>The value arrives already case-folded</strong> ({@code toLowerCase(Locale.ROOT)}),
   * because {@link UserLookup} implementations resolve usernames case-insensitively. Since 2.3.0
   * the ceremony service folds it before calling, so implementations MUST use the argument as given
   * and MUST NOT re-derive a bucket key from a differently-cased source — case variants of one
   * username would otherwise get independent budgets and multiply the effective limit against a
   * single account.
   *
   * @param username the case-folded username from the start ceremony request; never {@code null}
   * @return {@code true} when allowed; {@code false} when the per-username budget for the current
   *     window is exhausted
   * @since 0.9.1
   */
  boolean tryAcquireForUsername(String username);
}
