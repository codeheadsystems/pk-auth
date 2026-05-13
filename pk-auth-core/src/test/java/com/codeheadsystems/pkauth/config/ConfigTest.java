// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.AttestationConveyance;
import com.codeheadsystems.pkauth.api.ResidentKeyRequirement;
import com.codeheadsystems.pkauth.api.UserVerificationRequirement;
import java.time.Duration;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ConfigTest {

  @Test
  void relyingPartyConfigDefaults() {
    RelyingPartyConfig rp =
        new RelyingPartyConfig("example.com", "Example", Set.of("https://example.com"));
    assertThat(rp.id()).isEqualTo("example.com");
    assertThat(rp.icon()).isNull();
  }

  @Test
  void relyingPartyConfigValidations() {
    assertThatThrownBy(() -> new RelyingPartyConfig("", "n", Set.of("https://x")))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new RelyingPartyConfig("x", "", Set.of("https://x")))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new RelyingPartyConfig("x", "n", Set.of()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void ceremonyConfigDefaults() {
    CeremonyConfig c = CeremonyConfig.defaults();
    assertThat(c.challengeTtl()).isEqualTo(Duration.ofMinutes(5));
    assertThat(c.userVerification()).isEqualTo(UserVerificationRequirement.PREFERRED);
    assertThat(c.residentKey()).isEqualTo(ResidentKeyRequirement.PREFERRED);
    assertThat(c.attestationConveyance()).isEqualTo(AttestationConveyance.NONE);
    assertThat(c.counterRegression()).isEqualTo(CounterRegressionPolicy.REJECT);
  }

  @Test
  void ceremonyConfigRejectsNonPositiveTtl() {
    assertThatThrownBy(
            () ->
                new CeremonyConfig(
                    Duration.ZERO,
                    UserVerificationRequirement.PREFERRED,
                    ResidentKeyRequirement.PREFERRED,
                    AttestationConveyance.NONE,
                    CounterRegressionPolicy.REJECT))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void counterRegressionPolicyValues() {
    assertThat(CounterRegressionPolicy.values())
        .containsExactly(CounterRegressionPolicy.REJECT, CounterRegressionPolicy.WARN);
  }
}
