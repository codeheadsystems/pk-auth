// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.jwt.JwtConfig;
import com.codeheadsystems.pkauth.refresh.RefreshTokenConfig;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Unit-tests the config-building {@link PkAuthFactory} bean methods directly, covering the
 * validation and TTL-defaulting branches that the integration context (which only ever supplies one
 * valid configuration) cannot reach.
 */
class PkAuthFactoryConfigTest {

  private final PkAuthFactory factory = new PkAuthFactory();

  private static PkAuthConfiguration config() {
    PkAuthConfiguration c = new PkAuthConfiguration();
    PkAuthConfiguration.RelyingParty rp = new PkAuthConfiguration.RelyingParty();
    rp.setId("example.com");
    rp.setName("Example");
    rp.setOrigins(List.of("https://example.com"));
    c.setRelyingParty(rp);
    PkAuthConfiguration.Jwt jwt = new PkAuthConfiguration.Jwt();
    jwt.setIssuer("https://pkauth.example.com");
    jwt.setAudience("https://app.example.com");
    jwt.setSecret("pk-auth-micronaut-test-secret-32b!");
    c.setJwt(jwt);
    PkAuthConfiguration.Ceremony ceremony = new PkAuthConfiguration.Ceremony();
    ceremony.setChallengeTtl(Duration.ofMinutes(5));
    c.setCeremony(ceremony);
    c.setRefresh(new PkAuthConfiguration.Refresh());
    return c;
  }

  // -- relyingPartyConfig -------------------------------------------------------------------

  @Test
  void relyingPartyConfigBuildsFromValidConfig() {
    RelyingPartyConfig rp = factory.relyingPartyConfig(config());
    assertThat(rp.id()).isEqualTo("example.com");
    assertThat(rp.origins()).containsExactly("https://example.com");
  }

  @Test
  void relyingPartyConfigRejectsBlankId() {
    PkAuthConfiguration c = config();
    c.getRelyingParty().setId("  ");
    assertThatThrownBy(() -> factory.relyingPartyConfig(c))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("relying-party");
  }

  @Test
  void relyingPartyConfigRejectsNullOrigins() {
    PkAuthConfiguration c = config();
    c.getRelyingParty().setOrigins(null);
    assertThatThrownBy(() -> factory.relyingPartyConfig(c))
        .isInstanceOf(IllegalStateException.class);
  }

  // -- jwtConfig ----------------------------------------------------------------------------

  @Test
  void jwtConfigDefaultsTtlAndUsesSinglePolicyWhenNoOverrides() {
    JwtConfig cfg = factory.jwtConfig(config());
    assertThat(cfg.issuer()).isEqualTo("https://pkauth.example.com");
    // No overrides → single-policy → only the default audience is allowed.
    assertThat(cfg.allowedAudiences()).containsExactly("https://app.example.com");
  }

  @Test
  void jwtConfigUsesFixedPolicyWhenOverridesPresent() {
    PkAuthConfiguration c = config();
    c.getJwt().setDefaultTtl(Duration.ofMinutes(30));
    c.getJwt().setTtlsByAudience(Map.of("cli", Duration.ofHours(8)));
    JwtConfig cfg = factory.jwtConfig(c);
    assertThat(cfg.allowedAudiences()).contains("https://app.example.com", "cli");
  }

  @Test
  void jwtConfigRejectsBlankIssuerOrAudience() {
    PkAuthConfiguration blankIssuer = config();
    blankIssuer.getJwt().setIssuer(" ");
    assertThatThrownBy(() -> factory.jwtConfig(blankIssuer))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("issuer");

    PkAuthConfiguration nullAud = config();
    nullAud.getJwt().setAudience(null);
    assertThatThrownBy(() -> factory.jwtConfig(nullAud)).isInstanceOf(IllegalStateException.class);
  }

  // -- ceremonyConfig / refreshTokenConfig --------------------------------------------------

  @Test
  void ceremonyConfigCarriesChallengeTtlAndDefaultsTheRest() {
    var cc = factory.ceremonyConfig(config());
    assertThat(cc.challengeTtl()).isEqualTo(Duration.ofMinutes(5));
    assertThat(cc.userVerification()).isNotNull();
  }

  @Test
  void refreshTokenConfigDefaultsWhenUnset() {
    RefreshTokenConfig rc = factory.refreshTokenConfig(config());
    assertThat(rc.ttlPolicy().refreshTtl("any")).isEqualTo(RefreshTokenConfig.DEFAULT_REFRESH_TTL);
    assertThat(rc.cleanupRetention()).isEqualTo(RefreshTokenConfig.DEFAULT_CLEANUP_RETENTION);
  }

  @Test
  void refreshTokenConfigUsesFixedPolicyAndExplicitRetentionWhenSet() {
    PkAuthConfiguration c = config();
    c.getRefresh().setDefaultTtl(Duration.ofDays(7));
    c.getRefresh().setTtlsByAudience(Map.of("cli", Duration.ofDays(90)));
    c.getRefresh().setCleanupRetention(Duration.ofDays(10));
    RefreshTokenConfig rc = factory.refreshTokenConfig(c);
    assertThat(rc.ttlPolicy().refreshTtl("cli")).isEqualTo(Duration.ofDays(90));
    assertThat(rc.ttlPolicy().refreshTtl("other")).isEqualTo(Duration.ofDays(7));
    assertThat(rc.cleanupRetention()).isEqualTo(Duration.ofDays(10));
  }
}
