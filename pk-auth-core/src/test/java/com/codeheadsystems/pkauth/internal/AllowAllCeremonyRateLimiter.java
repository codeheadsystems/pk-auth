// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.internal;

import com.codeheadsystems.pkauth.spi.CeremonyRateLimiter;
import org.jspecify.annotations.Nullable;

/** Test-only {@link CeremonyRateLimiter} that never denies, for tests not exercising throttling. */
enum AllowAllCeremonyRateLimiter implements CeremonyRateLimiter {
  INSTANCE;

  @Override
  public boolean tryAcquireForIp(@Nullable String ip) {
    return true;
  }

  @Override
  public boolean tryAcquireForUsername(String username) {
    return true;
  }
}
