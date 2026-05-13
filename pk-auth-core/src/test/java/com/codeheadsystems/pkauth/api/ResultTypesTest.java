// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.credential.AuthenticatorData;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ResultTypesTest {

  @Test
  void registrationResultSuccessConstruction() {
    UserHandle uh = UserHandle.random();
    CredentialRecord cred =
        new CredentialRecord(
            new byte[] {1, 2, 3},
            uh,
            new byte[] {4, 5},
            0L,
            "Yubikey",
            null,
            Set.of("usb"),
            true,
            true,
            Instant.now(),
            null);
    AuthenticatorData authData =
        new AuthenticatorData(new byte[] {1}, true, true, false, false, true, false, 0L);

    RegistrationResult result = new RegistrationResult.Success(cred, authData);

    String formatted =
        switch (result) {
          case RegistrationResult.Success s -> "ok:" + s.credential().label();
          case RegistrationResult.InvalidChallenge ic -> "ic:" + ic.detail();
          case RegistrationResult.OriginMismatch om -> "om:" + om.expected();
          case RegistrationResult.AttestationRejected ar -> "ar:" + ar.reason();
          case RegistrationResult.DuplicateCredential dc -> "dup";
          case RegistrationResult.InvalidPayload ip -> "ip:" + ip.detail();
        };
    assertThat(formatted).isEqualTo("ok:Yubikey");
  }

  @Test
  void registrationResultVariantsBuildAndValidate() {
    assertThat(new RegistrationResult.InvalidChallenge("nope").detail()).isEqualTo("nope");
    assertThat(new RegistrationResult.OriginMismatch("a", "b").actual()).isEqualTo("b");
    assertThat(new RegistrationResult.AttestationRejected("fail").reason()).isEqualTo("fail");
    assertThat(new RegistrationResult.InvalidPayload("bad").detail()).isEqualTo("bad");

    RegistrationResult.DuplicateCredential dup =
        new RegistrationResult.DuplicateCredential(new byte[] {7, 8, 9});
    assertThat(dup.credentialId()).containsExactly(7, 8, 9);
    assertThat(dup)
        .isEqualTo(new RegistrationResult.DuplicateCredential(new byte[] {7, 8, 9}))
        .hasSameHashCodeAs(new RegistrationResult.DuplicateCredential(new byte[] {7, 8, 9}));
    assertThat(dup.toString()).contains("070809");

    assertThatThrownBy(() -> new RegistrationResult.InvalidChallenge(null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void assertionResultSuccessConstructionAndAccessors() {
    UserHandle uh = UserHandle.random();
    AssertionResult.Success success = new AssertionResult.Success(uh, new byte[] {10, 11}, 42L);

    assertThat(success.userHandle()).isEqualTo(uh);
    assertThat(success.credentialId()).containsExactly(10, 11);
    assertThat(success.signCount()).isEqualTo(42L);
    assertThat(success)
        .isEqualTo(new AssertionResult.Success(uh, new byte[] {10, 11}, 42L))
        .hasSameHashCodeAs(new AssertionResult.Success(uh, new byte[] {10, 11}, 42L));
    assertThat(success.toString()).contains("0a0b").contains("42");
    assertThatThrownBy(() -> new AssertionResult.Success(uh, new byte[] {0}, -1))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void assertionResultVariantsExhaustiveSwitch() {
    AssertionResult[] cases = {
      new AssertionResult.UnknownCredential(new byte[] {1}),
      new AssertionResult.InvalidChallenge("x"),
      new AssertionResult.OriginMismatch("a", "b"),
      new AssertionResult.CounterRegression(5, 4),
      new AssertionResult.UserVerificationRequired(),
      new AssertionResult.InvalidSignature(),
    };
    for (AssertionResult r : cases) {
      String tag =
          switch (r) {
            case AssertionResult.Success s -> "success";
            case AssertionResult.UnknownCredential uc -> "unknown:" + uc.credentialId().length;
            case AssertionResult.InvalidChallenge ic -> "ic";
            case AssertionResult.OriginMismatch om -> "om";
            case AssertionResult.CounterRegression cr -> "cr:" + cr.stored() + "/" + cr.received();
            case AssertionResult.UserVerificationRequired uvr -> "uvr";
            case AssertionResult.InvalidSignature is -> "is";
          };
      assertThat(tag).isNotBlank();
    }

    AssertionResult.UnknownCredential uc1 =
        new AssertionResult.UnknownCredential(new byte[] {1, 2});
    AssertionResult.UnknownCredential uc2 =
        new AssertionResult.UnknownCredential(new byte[] {1, 2});
    assertThat(uc1).isEqualTo(uc2).hasSameHashCodeAs(uc2);
    assertThat(uc1.toString()).contains("0102");
  }
}
