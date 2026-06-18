// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.Transport;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Read-side decode of the COSE algorithm recorded on a stored credential (no schema change). */
class CredentialAlgorithmsTest {

  private static final ObjectConverter OBJECT_CONVERTER = new ObjectConverter();

  @Test
  void coseAlgorithmReadsEs256FromStoredKey() {
    CredentialRecord record = credentialWithEs256Key();

    // ES256 == COSE identifier -7.
    assertThat(CredentialAlgorithms.coseAlgorithm(record)).isEqualTo(-7);
    assertThat(CredentialAlgorithms.usesAlgorithm(record, -7)).isTrue();
    assertThat(CredentialAlgorithms.usesAlgorithm(record, -257)).isFalse();
  }

  @Test
  void undecodableKeyThrows() {
    CredentialRecord broken =
        new CredentialRecord(
            CredentialId.of(new byte[] {1, 2, 3}),
            UserHandle.of(new byte[16]),
            new byte[] {0x01}, // not a valid COSE key
            0L,
            "Broken",
            null,
            Set.of(Transport.USB),
            false,
            false,
            Instant.EPOCH,
            null);

    assertThatThrownBy(() -> CredentialAlgorithms.coseAlgorithm(broken))
        .isInstanceOf(IllegalStateException.class);
  }

  private static CredentialRecord credentialWithEs256Key() {
    byte[] point = new byte[65];
    point[0] = 0x04;
    for (int i = 1; i < point.length; i++) {
      point[i] = (byte) i;
    }
    EC2COSEKey key = EC2COSEKey.createFromUncompressedECCKey(point);
    byte[] cose = OBJECT_CONVERTER.getCborMapper().writeValueAsBytes(key);
    return new CredentialRecord(
        CredentialId.of(new byte[] {9, 9, 9}),
        UserHandle.of(new byte[16]),
        cose,
        0L,
        "ES256 key",
        null,
        Set.of(Transport.INTERNAL),
        false,
        false,
        Instant.EPOCH,
        null);
  }
}
