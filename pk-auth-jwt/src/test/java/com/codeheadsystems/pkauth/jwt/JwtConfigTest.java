// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Covers the host-config-to-domain-config {@link JwtConfig#from} translation. */
class JwtConfigTest {

  @Test
  void fromAppliesDocumentedDefaultsWhenTtlNull() {
    JwtConfig config = JwtConfig.from("iss", "aud", null, null);
    assertThat(config.issuer()).isEqualTo("iss");
    assertThat(config.defaultAudience()).isEqualTo("aud");
    assertThat(config.notBeforeSkew()).isEqualTo(JwtConfig.DEFAULT_NBF_SKEW);
    assertThat(config.clockSkew()).isEqualTo(JwtConfig.DEFAULT_CLOCK_SKEW);
    assertThat(config.ttlPolicy().accessTtl("aud")).isEqualTo(JwtConfig.DEFAULT_TOKEN_TTL);
    assertThat(config.ttlPolicy().knownAudiences()).isEmpty();
  }

  @Test
  void fromHonorsExplicitDefaultTtl() {
    JwtConfig config = JwtConfig.from("iss", "aud", Duration.ofMinutes(5), null);
    assertThat(config.ttlPolicy().accessTtl("aud")).isEqualTo(Duration.ofMinutes(5));
  }

  @Test
  void fromBuildsPerAudiencePolicyFromOverrides() {
    JwtConfig config =
        JwtConfig.from("iss", "aud", Duration.ofHours(1), Map.of("cli", Duration.ofHours(8)));
    assertThat(config.ttlPolicy().accessTtl("cli")).isEqualTo(Duration.ofHours(8));
    assertThat(config.ttlPolicy().accessTtl("aud")).isEqualTo(Duration.ofHours(1));
    assertThat(config.allowedAudiences()).contains("aud", "cli");
  }
}
