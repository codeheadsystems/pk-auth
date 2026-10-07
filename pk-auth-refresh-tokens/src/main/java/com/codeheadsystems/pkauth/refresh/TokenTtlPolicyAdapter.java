// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh;

import com.codeheadsystems.pkauth.jwt.TokenTtlPolicy;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;

/**
 * Presents a {@link TokenTtlPolicy} as a {@link RefreshTtlPolicy}. The built-in refresh factories
 * share their validation, freezing, and audience dispatch with the access-token factories, so they
 * build a {@link TokenTtlPolicy} and wrap it here rather than duplicating that logic.
 */
final class TokenTtlPolicyAdapter implements RefreshTtlPolicy {

  private final TokenTtlPolicy delegate;

  TokenTtlPolicyAdapter(TokenTtlPolicy delegate) {
    this.delegate = Objects.requireNonNull(delegate, "delegate");
  }

  @Override
  public Duration refreshTtl(String audience) {
    return delegate.accessTtl(audience);
  }

  @Override
  public Set<String> knownAudiences() {
    return delegate.knownAudiences();
  }

  @Override
  public String toString() {
    // "TokenTtlPolicy.single(PT336H)" renders as "RefreshTtlPolicy.single(PT336H)", matching the
    // output these factories produced before they delegated.
    return "Refresh" + delegate.toString().replaceFirst("^Token", "");
  }
}
