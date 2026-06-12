// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import java.time.Duration;
import java.util.Objects;

/**
 * Sealed sum of admin-operation outcomes, mirroring the {@code *Result} pattern used elsewhere in
 * pk-auth-core. Adapter modules map each variant to a stable HTTP status via a shared {@code
 * AdminResultMapper}.
 *
 * @param <T> the payload type for {@link Success}.
 * @since 0.9.0
 */
public sealed interface AdminResult<T> {

  /** Operation succeeded. */
  record Success<T>(T value) implements AdminResult<T> {}

  /** The targeted resource (credential, user, …) doesn't exist. */
  record NotFound<T>() implements AdminResult<T> {}

  /** Authorizer denied the operation. */
  record Forbidden<T>() implements AdminResult<T> {}

  /** Request payload failed structural / semantic validation. */
  record ValidationFailed<T>(String detail) implements AdminResult<T> {
    public ValidationFailed {
      Objects.requireNonNull(detail, "detail");
    }
  }

  /** Operation would violate a server-side invariant (e.g., last-credential guard). */
  record Conflict<T>(String detail) implements AdminResult<T> {
    public Conflict {
      Objects.requireNonNull(detail, "detail");
    }
  }

  /** Rate limit hit; {@code retryAfter} is a best-effort hint to the caller. */
  record RateLimited<T>(Duration retryAfter) implements AdminResult<T> {
    public RateLimited {
      Objects.requireNonNull(retryAfter, "retryAfter");
    }
  }
}
