// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.AttestationConveyance;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import org.junit.jupiter.api.Test;

class SpiHelpersTest {

  @Test
  void clockProviderSystem() {
    Instant before = Instant.now();
    Instant now = ClockProvider.system().now();
    Instant after = Instant.now();
    assertThat(now).isBetween(before, after);
  }

  @Test
  void clockProviderFromClock() {
    Clock fixed = Clock.fixed(Instant.parse("2024-01-01T00:00:00Z"), ZoneOffset.UTC);
    assertThat(ClockProvider.fromClock(fixed).now())
        .isEqualTo(Instant.parse("2024-01-01T00:00:00Z"));
  }

  @Test
  void originValidatorStrict() {
    RelyingPartyConfig cfg =
        new RelyingPartyConfig("example.com", "Example", Set.of("https://example.com"));
    OriginValidator v = OriginValidator.strict(cfg);
    assertThat(v.isAllowed("https://example.com")).isTrue();
    assertThat(v.isAllowed("https://evil.com")).isFalse();
    assertThat(v.isAllowed(null)).isFalse();
    assertThatThrownBy(() -> OriginValidator.strict(null)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void attestationTrustPolicyNone() {
    AttestationTrustPolicy policy = AttestationTrustPolicy.none();
    AttestationTrustPolicy.AttestationData data =
        new AttestationTrustPolicy.AttestationData(null, "packed", AttestationConveyance.NONE);
    AttestationTrustPolicy.Decision decision = policy.evaluate(data);
    assertThat(decision).isInstanceOf(AttestationTrustPolicy.Decision.Trusted.class);
  }

  @Test
  void attestationTrustPolicyDecisionRejected() {
    AttestationTrustPolicy.Decision.Rejected rej =
        new AttestationTrustPolicy.Decision.Rejected("no good");
    assertThat(rej.reason()).isEqualTo("no good");
    assertThatThrownBy(() -> new AttestationTrustPolicy.Decision.Rejected(null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void userLookupViewRequiresNonNull() {
    assertThatThrownBy(() -> new UserLookup.UserView(null, "u", "U", false, false))
        .isInstanceOf(NullPointerException.class);
    UserLookup.UserView v =
        new UserLookup.UserView(UserHandle.of(new byte[] {1}), "u", "U", true, false);
    assertThat(v.emailVerified()).isTrue();
    assertThat(v.phoneVerified()).isFalse();
  }
}
