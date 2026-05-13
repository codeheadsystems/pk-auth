// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.config;

/**
 * What to do when an asserted signature counter is less than or equal to the stored counter.
 *
 * <p>Synced passkeys (iCloud Keychain, Google Password Manager, …) typically report a counter of
 * zero across all devices, so counter regression is normal for those credentials.
 */
public enum CounterRegressionPolicy {
  /** Reject the assertion (cloning risk). Default for hardware-token-heavy deployments. */
  REJECT,

  /** Log a warning but accept the assertion. Appropriate for synced-passkey-heavy deployments. */
  WARN
}
