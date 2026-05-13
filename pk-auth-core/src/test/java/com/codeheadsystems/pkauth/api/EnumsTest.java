// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class EnumsTest {

  @Test
  void userVerificationRequirementValues() {
    assertThat(UserVerificationRequirement.values())
        .containsExactly(
            UserVerificationRequirement.REQUIRED,
            UserVerificationRequirement.PREFERRED,
            UserVerificationRequirement.DISCOURAGED);
    assertThat(UserVerificationRequirement.valueOf("REQUIRED"))
        .isEqualTo(UserVerificationRequirement.REQUIRED);
  }

  @Test
  void residentKeyRequirementValues() {
    assertThat(ResidentKeyRequirement.values())
        .containsExactly(
            ResidentKeyRequirement.REQUIRED,
            ResidentKeyRequirement.PREFERRED,
            ResidentKeyRequirement.DISCOURAGED);
  }

  @Test
  void attestationConveyanceValues() {
    assertThat(AttestationConveyance.values())
        .containsExactly(
            AttestationConveyance.NONE,
            AttestationConveyance.INDIRECT,
            AttestationConveyance.DIRECT,
            AttestationConveyance.ENTERPRISE);
  }

  @Test
  void authenticatorAttachmentValues() {
    assertThat(AuthenticatorAttachment.values())
        .containsExactly(AuthenticatorAttachment.PLATFORM, AuthenticatorAttachment.CROSS_PLATFORM);
  }
}
