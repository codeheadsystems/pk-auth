// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.jwt.JwtConfig;
import com.codeheadsystems.pkauth.refresh.RefreshTokenConfig;
import com.codeheadsystems.pkauth.spring.config.PkAuthProperties;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Unit-tests the config-building {@code @Bean} methods of {@link PkAuthAutoConfiguration} directly,
 * covering the required-block validation and TTL-defaulting branches that a single Spring context
 * (one valid binding) cannot exercise.
 */
class PkAuthAutoConfigurationUnitTest {

  private final PkAuthAutoConfiguration autoConfig = new PkAuthAutoConfiguration();

  private static PkAuthProperties.RelyingParty rp() {
    return new PkAuthProperties.RelyingParty(
        "example.com", "Example", Set.of("https://example.com"));
  }

  private static PkAuthProperties.Jwt jwt(Duration defaultTtl, Map<String, Duration> overrides) {
    return new PkAuthProperties.Jwt(
        "https://pkauth.example.com",
        "https://app.example.com",
        "pk-auth-spring-test-secret-bytes-32!!",
        defaultTtl,
        overrides);
  }

  private static PkAuthProperties props(
      PkAuthProperties.RelyingParty rp,
      PkAuthProperties.Jwt jwt,
      PkAuthProperties.Refresh refresh) {
    return new PkAuthProperties(rp, jwt, null, null, refresh, false);
  }

  // -- relyingParty -------------------------------------------------------------------------

  @Test
  void relyingPartyConfigBuildsFromValidProps() {
    RelyingPartyConfig cfg =
        autoConfig.pkAuthRelyingPartyConfig(props(rp(), jwt(null, null), null));
    assertThat(cfg.id()).isEqualTo("example.com");
    assertThat(cfg.origins()).containsExactly("https://example.com");
  }

  @Test
  void relyingPartyConfigThrowsWhenBlockMissing() {
    assertThatThrownBy(
            () -> autoConfig.pkAuthRelyingPartyConfig(props(null, jwt(null, null), null)))
        .isInstanceOf(IllegalStateException.class);
  }

  // -- jwt ----------------------------------------------------------------------------------

  @Test
  void jwtConfigUsesSinglePolicyWhenNoOverrides() {
    JwtConfig cfg = autoConfig.pkAuthJwtConfig(props(rp(), jwt(null, null), null));
    assertThat(cfg.issuer()).isEqualTo("https://pkauth.example.com");
    assertThat(cfg.allowedAudiences()).containsExactly("https://app.example.com");
  }

  @Test
  void jwtConfigUsesFixedPolicyWhenOverridesPresent() {
    JwtConfig cfg =
        autoConfig.pkAuthJwtConfig(
            props(rp(), jwt(Duration.ofMinutes(30), Map.of("cli", Duration.ofHours(8))), null));
    assertThat(cfg.allowedAudiences()).contains("https://app.example.com", "cli");
  }

  @Test
  void jwtConfigThrowsWhenJwtBlockMissing() {
    assertThatThrownBy(() -> autoConfig.pkAuthJwtConfig(props(rp(), null, null)))
        .isInstanceOf(IllegalStateException.class);
  }

  // -- refresh ------------------------------------------------------------------------------

  @Test
  void refreshTokenConfigDefaultsWhenUnset() {
    RefreshTokenConfig cfg =
        autoConfig.pkAuthRefreshTokenConfig(props(rp(), jwt(null, null), null));
    assertThat(cfg.ttlPolicy().refreshTtl("any")).isEqualTo(RefreshTokenConfig.DEFAULT_REFRESH_TTL);
    assertThat(cfg.cleanupRetention()).isEqualTo(RefreshTokenConfig.DEFAULT_CLEANUP_RETENTION);
  }

  @Test
  void refreshTokenConfigUsesFixedPolicyAndExplicitRetention() {
    PkAuthProperties.Refresh refresh =
        new PkAuthProperties.Refresh(
            Duration.ofDays(7), Map.of("cli", Duration.ofDays(90)), Duration.ofDays(10), null);
    RefreshTokenConfig cfg =
        autoConfig.pkAuthRefreshTokenConfig(props(rp(), jwt(null, null), refresh));
    assertThat(cfg.ttlPolicy().refreshTtl("cli")).isEqualTo(Duration.ofDays(90));
    assertThat(cfg.ttlPolicy().refreshTtl("other")).isEqualTo(Duration.ofDays(7));
    assertThat(cfg.cleanupRetention()).isEqualTo(Duration.ofDays(10));
  }
}
