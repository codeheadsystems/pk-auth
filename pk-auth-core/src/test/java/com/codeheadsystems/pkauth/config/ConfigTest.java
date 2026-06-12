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
    assertThat(rp.name()).isEqualTo("Example");
    assertThat(rp.origins()).containsExactly("https://example.com");
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
    assertThat(c.userVerification()).isEqualTo(UserVerificationRequirement.REQUIRED);
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
  void relyingPartyConfigFromValidatesAndCopies() {
    RelyingPartyConfig rp =
        RelyingPartyConfig.from("example.com", "Example", java.util.List.of("https://example.com"));
    assertThat(rp.origins()).containsExactly("https://example.com");
  }

  @Test
  void relyingPartyConfigFromRejectsMissingFieldsWithCanonicalMessage() {
    assertThatThrownBy(() -> RelyingPartyConfig.from(null, "n", Set.of("https://x")))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("pkauth.relying-party");
    assertThatThrownBy(() -> RelyingPartyConfig.from("x", "  ", Set.of("https://x")))
        .isInstanceOf(IllegalStateException.class);
    assertThatThrownBy(() -> RelyingPartyConfig.from("x", "n", Set.of()))
        .isInstanceOf(IllegalStateException.class);
    assertThatThrownBy(() -> RelyingPartyConfig.from("x", "n", null))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  void ceremonyConfigFromCoalescesNullsToDefaultsAndNeverWeakens() {
    // All null -> every knob takes the conservative default.
    CeremonyConfig allDefaults = CeremonyConfig.from(null, null, null, null, null);
    assertThat(allDefaults).isEqualTo(CeremonyConfig.defaults());

    // A supplied value overrides only that knob; the rest stay at the secure defaults.
    CeremonyConfig overridden = CeremonyConfig.from(Duration.ofMinutes(2), null, null, null, null);
    assertThat(overridden.challengeTtl()).isEqualTo(Duration.ofMinutes(2));
    assertThat(overridden.userVerification()).isEqualTo(UserVerificationRequirement.REQUIRED);
    assertThat(overridden.counterRegression()).isEqualTo(CounterRegressionPolicy.REJECT);
  }
}
