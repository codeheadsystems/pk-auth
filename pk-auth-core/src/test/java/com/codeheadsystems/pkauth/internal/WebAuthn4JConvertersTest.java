// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.internal;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.AuthenticationResponseJson;
import com.codeheadsystems.pkauth.api.AuthenticationResponseJson.AuthenticatorAssertionResponseJson;
import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson.AuthenticatorAttestationResponseJson;
import com.codeheadsystems.pkauth.api.Transport;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.api.UserVerificationRequirement;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class WebAuthn4JConvertersTest {

  private final ObjectConverter objectConverter = new ObjectConverter();

  @Test
  void serverPropertyCarriesOriginsRpIdAndChallenge() {
    RelyingPartyConfig rp =
        new RelyingPartyConfig("example.com", "Example", Set.of("https://example.com"));
    byte[] challenge = {1, 2, 3};
    var sp = WebAuthn4JConverters.serverProperty(rp, challenge);
    assertThat(sp.getRpId()).isEqualTo("example.com");
    assertThat(sp.getChallenge().getValue()).containsExactly(1, 2, 3);
  }

  @Test
  void toRegistrationRequestPassesThroughBytes() {
    RegistrationResponseJson resp =
        new RegistrationResponseJson(
            new byte[] {1},
            new byte[] {1},
            new AuthenticatorAttestationResponseJson(
                new byte[] {0x10}, new byte[] {0x20}, List.of("usb"), null, null, null),
            null,
            null,
            "public-key");
    var w4j = WebAuthn4JConverters.toRegistrationRequest(resp);
    assertThat(w4j.getClientDataJSON()).containsExactly(0x10);
    assertThat(w4j.getAttestationObject()).containsExactly(0x20);
    assertThat(w4j.getTransports()).containsExactly("usb");
  }

  @Test
  void toRegistrationRequestHandlesNullTransports() {
    RegistrationResponseJson resp =
        new RegistrationResponseJson(
            new byte[] {1},
            new byte[] {1},
            new AuthenticatorAttestationResponseJson(
                new byte[] {0x10}, new byte[] {0x20}, null, null, null, null),
            null,
            null,
            "public-key");
    var w4j = WebAuthn4JConverters.toRegistrationRequest(resp);
    assertThat(w4j.getTransports()).isEmpty();
  }

  @Test
  void toAuthenticationRequestPassesThroughBytes() {
    AuthenticationResponseJson resp =
        new AuthenticationResponseJson(
            new byte[] {1},
            new byte[] {1},
            new AuthenticatorAssertionResponseJson(
                new byte[] {0x30}, new byte[] {0x31}, new byte[] {0x32}, new byte[] {0x33}),
            null,
            null,
            "public-key");
    var w4j = WebAuthn4JConverters.toAuthenticationRequest(resp);
    assertThat(w4j.getClientDataJSON()).containsExactly(0x30);
    assertThat(w4j.getAuthenticatorData()).containsExactly(0x31);
    assertThat(w4j.getSignature()).containsExactly(0x32);
    assertThat(w4j.getUserHandle()).containsExactly(0x33);
  }

  @Test
  void coseKeyRoundTripsThroughSerializer() {
    byte[] point = new byte[65];
    point[0] = 0x04;
    for (int i = 1; i < point.length; i++) {
      point[i] = (byte) i;
    }
    EC2COSEKey original = EC2COSEKey.createFromUncompressedECCKey(point);
    byte[] bytes = WebAuthn4JConverters.serializeCoseKey(original, objectConverter);
    assertThat(bytes).isNotEmpty();
    var key2 =
        objectConverter
            .getCborMapper()
            .readValue(bytes, com.webauthn4j.data.attestation.authenticator.COSEKey.class);
    assertThat(key2).isNotNull();
  }

  @Test
  void toW4jCredentialRecordRebuilds() {
    byte[] point = new byte[65];
    point[0] = 0x04;
    for (int i = 1; i < point.length; i++) {
      point[i] = (byte) i;
    }
    EC2COSEKey key = EC2COSEKey.createFromUncompressedECCKey(point);
    byte[] coseBytes = WebAuthn4JConverters.serializeCoseKey(key, objectConverter);
    CredentialRecord cred =
        new CredentialRecord(
            CredentialId.of(new byte[] {1, 2, 3}),
            UserHandle.random(),
            coseBytes,
            7L,
            "Test",
            null,
            Set.of(Transport.USB),
            true,
            true,
            Instant.now(),
            null);
    var w4j = WebAuthn4JConverters.toW4jCredentialRecord(cred, objectConverter);
    assertThat(w4j.getCounter()).isEqualTo(7L);
    assertThat(w4j.getAttestedCredentialData().getCredentialId()).containsExactly(1, 2, 3);
  }

  @Test
  void userVerificationRequiredOnlyForRequired() {
    assertThat(WebAuthn4JConverters.userVerificationRequired(UserVerificationRequirement.REQUIRED))
        .isTrue();
    assertThat(WebAuthn4JConverters.userVerificationRequired(UserVerificationRequirement.PREFERRED))
        .isFalse();
  }
}
