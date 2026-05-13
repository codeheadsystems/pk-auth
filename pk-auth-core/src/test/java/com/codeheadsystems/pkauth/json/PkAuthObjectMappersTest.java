// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.json;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.AttestationConveyance;
import com.codeheadsystems.pkauth.api.AuthenticationResponseJson;
import com.codeheadsystems.pkauth.api.AuthenticationResponseJson.AuthenticatorAssertionResponseJson;
import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.PublicKeyCredentialCreationOptionsJson;
import com.codeheadsystems.pkauth.api.PublicKeyCredentialCreationOptionsJson.AuthenticatorSelectionCriteria;
import com.codeheadsystems.pkauth.api.PublicKeyCredentialCreationOptionsJson.PublicKeyCredentialDescriptor;
import com.codeheadsystems.pkauth.api.PublicKeyCredentialCreationOptionsJson.PublicKeyCredentialParameters;
import com.codeheadsystems.pkauth.api.PublicKeyCredentialCreationOptionsJson.RelyingParty;
import com.codeheadsystems.pkauth.api.PublicKeyCredentialCreationOptionsJson.UserInfo;
import com.codeheadsystems.pkauth.api.PublicKeyCredentialRequestOptionsJson;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson.AuthenticatorAttestationResponseJson;
import com.codeheadsystems.pkauth.api.ResidentKeyRequirement;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.api.UserVerificationRequirement;
import java.util.List;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.DatabindException;
import tools.jackson.databind.json.JsonMapper;

class PkAuthObjectMappersTest {

  private final JsonMapper mapper = PkAuthObjectMappers.create();

  @Test
  void byteArraySerializesAsBase64UrlNoPadding() {
    record Holder(byte[] data) {}
    String json = mapper.writeValueAsString(new Holder(new byte[] {(byte) 0xff}));
    assertThat(json).isEqualTo("{\"data\":\"_w\"}");
    Holder back = mapper.readValue(json, Holder.class);
    assertThat(back.data()).containsExactly(0xff);
  }

  @Test
  void userHandleRoundTrips() {
    record Holder(UserHandle handle) {}
    UserHandle uh = UserHandle.of(new byte[] {1, 2, 3});
    String json = mapper.writeValueAsString(new Holder(uh));
    assertThat(json).contains("AQID");
    Holder back = mapper.readValue(json, Holder.class);
    assertThat(back.handle()).isEqualTo(uh);
  }

  @Test
  void challengeIdRoundTrips() {
    record Holder(ChallengeId id) {}
    ChallengeId id = new ChallengeId("abc-123");
    String json = mapper.writeValueAsString(new Holder(id));
    assertThat(json).isEqualTo("{\"id\":\"abc-123\"}");
    assertThat(mapper.readValue(json, Holder.class).id()).isEqualTo(id);
  }

  @Test
  void nullPropertiesAreOmittedOnOutput() {
    StartAuthenticationRequest req = new StartAuthenticationRequest(null, null);
    String json = mapper.writeValueAsString(req);
    assertThat(json).isEqualTo("{}");
  }

  @Test
  void unknownPropertiesFailOnInput() {
    assertThatThrownBy(
            () -> mapper.readValue("{\"unknownField\":1}", StartAuthenticationRequest.class))
        .isInstanceOf(DatabindException.class);
  }

  @Test
  void enumsUseLowercaseWireFormat() {
    record Holder(UserVerificationRequirement uv) {}
    String json = mapper.writeValueAsString(new Holder(UserVerificationRequirement.REQUIRED));
    assertThat(json).isEqualTo("{\"uv\":\"required\"}");
    Holder back = mapper.readValue("{\"uv\":\"preferred\"}", Holder.class);
    assertThat(back.uv()).isEqualTo(UserVerificationRequirement.PREFERRED);
  }

  @Test
  void publicKeyCredentialCreationOptionsRoundTrips() {
    PublicKeyCredentialCreationOptionsJson opts =
        new PublicKeyCredentialCreationOptionsJson(
            new RelyingParty("example.com", "Example"),
            new UserInfo(new byte[] {1, 2}, "alice", "Alice"),
            new byte[] {3, 4, 5},
            List.of(new PublicKeyCredentialParameters("public-key", -7)),
            60000L,
            List.of(
                new PublicKeyCredentialDescriptor("public-key", new byte[] {9}, List.of("usb"))),
            new AuthenticatorSelectionCriteria(
                null,
                ResidentKeyRequirement.PREFERRED,
                true,
                UserVerificationRequirement.PREFERRED),
            AttestationConveyance.NONE,
            null);
    String json = mapper.writeValueAsString(opts);
    PublicKeyCredentialCreationOptionsJson back =
        mapper.readValue(json, PublicKeyCredentialCreationOptionsJson.class);
    assertThat(back.rp().id()).isEqualTo("example.com");
    assertThat(back.user().name()).isEqualTo("alice");
    assertThat(back.challenge()).containsExactly(3, 4, 5);
    assertThat(back.pubKeyCredParams()).hasSize(1);
    assertThat(back.attestation()).isEqualTo(AttestationConveyance.NONE);
  }

  @Test
  void publicKeyCredentialRequestOptionsRoundTrips() {
    PublicKeyCredentialRequestOptionsJson opts =
        new PublicKeyCredentialRequestOptionsJson(
            new byte[] {6, 7, 8},
            30000L,
            "example.com",
            null,
            UserVerificationRequirement.DISCOURAGED,
            null);
    String json = mapper.writeValueAsString(opts);
    PublicKeyCredentialRequestOptionsJson back =
        mapper.readValue(json, PublicKeyCredentialRequestOptionsJson.class);
    assertThat(back.challenge()).containsExactly(6, 7, 8);
    assertThat(back.rpId()).isEqualTo("example.com");
    assertThat(back.userVerification()).isEqualTo(UserVerificationRequirement.DISCOURAGED);
  }

  @Test
  void registrationResponseRoundTrips() {
    RegistrationResponseJson resp =
        new RegistrationResponseJson(
            new byte[] {0x10},
            new byte[] {0x10},
            new AuthenticatorAttestationResponseJson(
                new byte[] {0x20},
                new byte[] {0x21, 0x22},
                List.of("usb", "nfc"),
                null,
                null,
                null),
            null,
            null,
            "public-key");
    String json = mapper.writeValueAsString(resp);
    RegistrationResponseJson back = mapper.readValue(json, RegistrationResponseJson.class);
    assertThat(back.type()).isEqualTo("public-key");
    assertThat(back.response().clientDataJSON()).containsExactly(0x20);
    assertThat(back.response().attestationObject()).containsExactly(0x21, 0x22);
    assertThat(back.response().transports()).containsExactly("usb", "nfc");
  }

  @Test
  void authenticationResponseRoundTrips() {
    AuthenticationResponseJson resp =
        new AuthenticationResponseJson(
            new byte[] {0x30},
            new byte[] {0x30},
            new AuthenticatorAssertionResponseJson(
                new byte[] {0x31}, new byte[] {0x32}, new byte[] {0x33}, new byte[] {0x34}),
            null,
            null,
            "public-key");
    String json = mapper.writeValueAsString(resp);
    AuthenticationResponseJson back = mapper.readValue(json, AuthenticationResponseJson.class);
    assertThat(back.response().clientDataJSON()).containsExactly(0x31);
    assertThat(back.response().signature()).containsExactly(0x33);
    assertThat(back.response().userHandle()).containsExactly(0x34);
  }

  @Test
  void finishRegistrationRequestRoundTrips() {
    RegistrationResponseJson inner =
        new RegistrationResponseJson(
            new byte[] {0x10},
            new byte[] {0x10},
            new AuthenticatorAttestationResponseJson(
                new byte[] {0x20}, new byte[] {0x21}, null, null, null, null),
            null,
            null,
            "public-key");
    FinishRegistrationRequest req =
        new FinishRegistrationRequest(new ChallengeId("ch-1"), "alice", "Work laptop", inner);
    String json = mapper.writeValueAsString(req);
    FinishRegistrationRequest back = mapper.readValue(json, FinishRegistrationRequest.class);
    assertThat(back.username()).isEqualTo("alice");
    assertThat(back.label()).isEqualTo("Work laptop");
    assertThat(back.challengeId()).isEqualTo(new ChallengeId("ch-1"));
  }

  @Test
  void finishAuthenticationRequestRoundTrips() {
    FinishAuthenticationRequest req =
        new FinishAuthenticationRequest(
            new ChallengeId("ch-2"),
            new AuthenticationResponseJson(
                new byte[] {0x40},
                new byte[] {0x40},
                new AuthenticatorAssertionResponseJson(
                    new byte[] {0x41}, new byte[] {0x42}, new byte[] {0x43}, null),
                null,
                null,
                "public-key"));
    String json = mapper.writeValueAsString(req);
    FinishAuthenticationRequest back = mapper.readValue(json, FinishAuthenticationRequest.class);
    assertThat(back.challengeId().value()).isEqualTo("ch-2");
    assertThat(back.response().response().authenticatorData()).containsExactly(0x42);
  }

  @Test
  void startRegistrationRequestValidatesUsername() {
    assertThatThrownBy(() -> new StartRegistrationRequest("", null, null, null))
        .isInstanceOf(IllegalArgumentException.class);

    StartRegistrationRequest req = new StartRegistrationRequest("alice", "Alice", "lap", null);
    String json = mapper.writeValueAsString(req);
    StartRegistrationRequest back = mapper.readValue(json, StartRegistrationRequest.class);
    assertThat(back.username()).isEqualTo("alice");
    assertThat(back.displayName()).isEqualTo("Alice");
  }
}
