// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Validates {@link RefreshTokenConfig} compact-constructor guards and the {@code defaults()}. */
class RefreshTokenConfigTest {

  private final RefreshTtlPolicy policy = RefreshTtlPolicy.single(Duration.ofDays(14));

  @Test
  void defaultsResolveAudienceTtlThroughPolicy() {
    assertThat(RefreshTokenConfig.defaults().ttlPolicy().refreshTtl("web"))
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

  @Test
  void fromAppliesAllDocumentedDefaultsWhenNull() {
    RefreshTokenConfig config = RefreshTokenConfig.from(null, null, null);
    assertThat(config.secretBytes()).isEqualTo(RefreshTokenConfig.DEFAULT_SECRET_BYTES);
    assertThat(config.refreshIdBytes()).isEqualTo(RefreshTokenConfig.DEFAULT_REFRESH_ID_BYTES);
    assertThat(config.cleanupRetention()).isEqualTo(RefreshTokenConfig.DEFAULT_CLEANUP_RETENTION);
    assertThat(config.ttlPolicy().refreshTtl("web"))
        .isEqualTo(RefreshTokenConfig.DEFAULT_REFRESH_TTL);
    assertThat(config.ttlPolicy().knownAudiences()).isEmpty();
  }

  @Test
  void fromHonorsExplicitValuesAndPerAudienceOverrides() {
    RefreshTokenConfig config =
        RefreshTokenConfig.from(
            Duration.ofDays(7), Map.of("cli", Duration.ofDays(90)), Duration.ofDays(60));
    assertThat(config.cleanupRetention()).isEqualTo(Duration.ofDays(60));
    assertThat(config.ttlPolicy().refreshTtl("cli")).isEqualTo(Duration.ofDays(90));
    assertThat(config.ttlPolicy().refreshTtl("web")).isEqualTo(Duration.ofDays(7));
  }
}
