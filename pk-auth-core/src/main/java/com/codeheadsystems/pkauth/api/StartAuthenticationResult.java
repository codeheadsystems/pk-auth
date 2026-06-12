// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import java.util.Objects;

/**
 * Sealed result of {@code PasskeyAuthenticationService.startAuthentication}. Mirrors the {@code
 * finish*} ceremonies' result-sum discipline so a rate-limit refusal is a value, not an exception
 * thrown across the adapter boundary.
 *
 * <ul>
 *   <li>{@link Started} — the limiter allowed the call; carries the {@link
 *       StartAuthenticationResponse} envelope the browser consumes.
 *   <li>{@link RateLimited} — the configured {@code CeremonyRateLimiter} refused the call before
 *       any challenge was created; adapters map it to HTTP {@code 429}.
 * </ul>
 *
 * @since 1.3.1
 */
public sealed interface StartAuthenticationResult
    permits StartAuthenticationResult.Started, StartAuthenticationResult.RateLimited {

  /**
   * The limiter allowed the ceremony; {@code response} carries the WebAuthn request options.
   *
   * @param response the start-authentication envelope.
   * @since 1.3.1
   */
  record Started(StartAuthenticationResponse response) implements StartAuthenticationResult {
    public Started {
      Objects.requireNonNull(response, "response");
    }
  }

  /**
   * The configured rate limiter refused the call before any challenge was created.
   *
   * @param bucket which limiter bucket denied the call ({@code "ip"} or {@code "username"}).
   * @since 1.3.1
   */
  record RateLimited(String bucket) implements StartAuthenticationResult {
    public RateLimited {
      Objects.requireNonNull(bucket, "bucket");
    }
  }

  /**
   * Convenience for embedded/test callers that do not configure a rate limiter and therefore never
   * expect a refusal. Returns the {@link StartAuthenticationResponse} on {@link Started}; throws on
   * {@link RateLimited}. Adapter controllers must NOT use this — they pattern-match the sum so the
   * {@code 429} path is handled explicitly.
   *
   * @return the start-authentication envelope.
   * @throws IllegalStateException if this result is {@link RateLimited}.
   * @since 1.3.1
   */
  default StartAuthenticationResponse responseOrThrow() {
    if (this instanceof Started started) {
      return started.response();
    }
    throw new IllegalStateException(
        "ceremony was rate-limited (bucket=" + ((RateLimited) this).bucket() + ")");
  }
}
