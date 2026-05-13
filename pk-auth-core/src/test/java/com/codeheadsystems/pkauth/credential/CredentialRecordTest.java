// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class CredentialRecordTest {

  private CredentialRecord build() {
    return new CredentialRecord(
        new byte[] {1, 2},
        UserHandle.of(new byte[] {9}),
        new byte[] {3, 4},
        7L,
        "Yubikey",
        UUID.fromString("00000000-0000-0000-0000-000000000001"),
        Set.of("usb", "nfc"),
        true,
        false,
        Instant.parse("2024-01-01T00:00:00Z"),
        Instant.parse("2024-02-01T00:00:00Z"));
  }

  @Test
  void defensiveCopies() {
    byte[] credId = {1, 2, 3};
    byte[] pubKey = {4, 5, 6};
    CredentialRecord cred =
        new CredentialRecord(
            credId,
            UserHandle.random(),
            pubKey,
            0L,
            "x",
            null,
            Set.of(),
            false,
            false,
            Instant.now(),
            null);
    credId[0] = 99;
    pubKey[0] = 99;
    assertThat(cred.credentialId()[0]).isEqualTo((byte) 1);
    assertThat(cred.publicKeyCose()[0]).isEqualTo((byte) 4);
  }

  @Test
  void equalsHashCodeAndToString() {
    CredentialRecord a = build();
    CredentialRecord b = build();
    assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    assertThat(a.toString()).contains("Yubikey").contains("0102");
    assertThat(a).isNotEqualTo("nope");
  }

  @Test
  void toMetadataDropsPublicKey() {
    CredentialMetadata meta = build().toMetadata();
    assertThat(meta.label()).isEqualTo("Yubikey");
    assertThat(meta.transports()).containsExactlyInAnyOrder("usb", "nfc");
    assertThat(meta).isEqualTo(build().toMetadata()).hasSameHashCodeAs(build().toMetadata());
    assertThat(meta.toString()).contains("Yubikey");
  }

  @Test
  void rejectsInvalidArgs() {
    assertThatThrownBy(
            () ->
                new CredentialRecord(
                    new byte[0],
                    UserHandle.random(),
                    new byte[] {1},
                    0L,
                    "x",
                    null,
                    Set.of(),
                    false,
                    false,
                    Instant.now(),
                    null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () ->
                new CredentialRecord(
                    new byte[] {1},
                    UserHandle.random(),
                    new byte[0],
                    0L,
                    "x",
                    null,
                    Set.of(),
                    false,
                    false,
                    Instant.now(),
                    null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () ->
                new CredentialRecord(
                    new byte[] {1},
                    UserHandle.random(),
                    new byte[] {1},
                    -1L,
                    "x",
                    null,
                    Set.of(),
                    false,
                    false,
                    Instant.now(),
                    null))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
