// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import org.junit.jupiter.api.Test;

/** Validates {@link RefreshTokenConfig} compact-constructor guards and the {@code defaults()}. */
class RefreshTokenConfigTest {

  private final RefreshTtlPolicy policy = RefreshTtlPolicy.single(Duration.ofDays(14));

  @Test
  void defaultsUsePinnedConstants() {
    RefreshTokenConfig config = RefreshTokenConfig.defaults();
    assertThat(config.secretBytes()).isEqualTo(RefreshTokenConfig.DEFAULT_SECRET_BYTES);
    assertThat(config.refreshIdBytes()).isEqualTo(RefreshTokenConfig.DEFAULT_REFRESH_ID_BYTES);
    assertThat(config.cleanupRetention()).isEqualTo(RefreshTokenConfig.DEFAULT_CLEANUP_RETENTION);
    assertThat(config.ttlPolicy().refreshTtl("web"))
        .isEqualTo(RefreshTokenConfig.DEFAULT_REFRESH_TTL);
  }

  @Test
  void rejectsNullTtlPolicy() {
    assertThatThrownBy(() -> new RefreshTokenConfig(null, 32, 16, Duration.ofDays(30)))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void rejectsSecretBytesBelowMinimum() {
    assertThatThrownBy(() -> new RefreshTokenConfig(policy, 15, 16, Duration.ofDays(30)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("secretBytes");
  }

  @Test
  void rejectsRefreshIdBytesBelowMinimum() {
    assertThatThrownBy(() -> new RefreshTokenConfig(policy, 32, 7, Duration.ofDays(30)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("refreshIdBytes");
  }

  @Test
  void rejectsNullCleanupRetention() {
    assertThatThrownBy(() -> new RefreshTokenConfig(policy, 32, 16, null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void rejectsNegativeCleanupRetention() {
    assertThatThrownBy(() -> new RefreshTokenConfig(policy, 32, 16, Duration.ofDays(-1)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("cleanupRetention");
  }

  @Test
  void acceptsMinimumBoundaryValues() {
    RefreshTokenConfig config = new RefreshTokenConfig(policy, 16, 8, Duration.ZERO);
    assertThat(config.secretBytes()).isEqualTo(16);
    assertThat(config.refreshIdBytes()).isEqualTo(8);
    assertThat(config.cleanupRetention()).isEqualTo(Duration.ZERO);
  }
}
