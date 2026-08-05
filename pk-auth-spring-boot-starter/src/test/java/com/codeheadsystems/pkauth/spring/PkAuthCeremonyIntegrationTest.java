// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.codeheadsystems.pkauth.api.AuthenticationResponseJson;
import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResponse;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResponse;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.jwt.JwtVerificationResult;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.codeheadsystems.pkauth.testkit.FakeAuthenticator;
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import tools.jackson.databind.ObjectMapper;

/**
 * End-to-end ceremony test: register a passkey via {@code /auth/passkeys/registration/*}, assert
 * with that passkey via {@code /auth/passkeys/authentication/*}, and verify the returned JWT
 * validates against the application's {@code PkAuthJwtValidator}.
 */
@SpringBootTest(classes = PkAuthTestApplication.class)
class PkAuthCeremonyIntegrationTest {

  @Autowired private WebApplicationContext webApplicationContext;
  @Autowired private ObjectMapper objectMapper;
  @Autowired private PkAuthJwtValidator jwtValidator;
  @Autowired private UserLookup userLookup;
  @Autowired private RelyingPartyConfig relyingParty;

  private MockMvc mockMvc;
  private FakeAuthenticator authenticator;

  @BeforeEach
  void setUp() {
    // Don't apply Spring Security to MockMvc — the starter's filter chain permits
    // /auth/passkeys/** anyway and we don't want test-only authentication overrides changing the
    // path under test.
    mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    authenticator =
        FakeAuthenticator.builder()
            .origin(relyingParty.origins().iterator().next())
            .rpId(relyingParty.id())
            .objectConverter(new ObjectConverter())
            .build();
  }

  @Test
  void overlongUsernameIsRejectedAsBadRequestNotServerError() throws Exception {
    // The username bounds a rate-limiter cache key and drives getOrCreateHandle (which persists a
    // user row) on a permitAll endpoint, so it must be bounded. Asserting through the adapter,
    // not just the record, because what matters is that the refusal reaches the client as a 400 —
    // a 500 would mean the validation escaped as an unhandled exception.
    String tooLong = "a".repeat(StartRegistrationRequest.MAX_USERNAME_LENGTH + 1);
    mockMvc
        .perform(
            post("/auth/passkeys/registration/start")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + tooLong + "\",\"displayName\":\"x\"}"))
        .andExpect(status().isBadRequest());

    mockMvc
        .perform(
            post("/auth/passkeys/authentication/start")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + tooLong + "\"}"))
        .andExpect(status().isBadRequest());
  }

  @Test
  void usernameExactlyAtTheBoundIsAccepted() throws Exception {
    String atLimit = "a".repeat(StartRegistrationRequest.MAX_USERNAME_LENGTH);
    mockMvc
        .perform(
            post("/auth/passkeys/registration/start")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    objectMapper.writeValueAsString(
                        new StartRegistrationRequest(atLimit, "At Limit", null, null))))
        .andExpect(status().isOk());
  }

  @Test
  void registrationThenAssertionMintsValidJwt() throws Exception {
    // -- 1. Start registration ----------------------------------------------------------------
    StartRegistrationRequest startReg = new StartRegistrationRequest("alice", "Alice", null, null);
    MvcResult startResult =
        mockMvc
            .perform(
                post("/auth/passkeys/registration/start")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(startReg)))
            .andExpect(status().isOk())
            .andReturn();
    StartRegistrationResponse startResp =
        objectMapper.readValue(
            startResult.getResponse().getContentAsString(), StartRegistrationResponse.class);
    assertThat(startResp.challengeId()).isNotNull();

    // -- 2. Finish registration ---------------------------------------------------------------
    RegistrationResponseJson regResponse = authenticator.createRegistrationResponse(startResp);
    FinishRegistrationRequest finishReg =
        new FinishRegistrationRequest(startResp.challengeId(), "alice", "Test Key", regResponse);
    MvcResult finishResult =
        mockMvc
            .perform(
                post("/auth/passkeys/registration/finish")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(finishReg)))
            .andExpect(status().isOk())
            .andReturn();
    assertThat(finishResult.getResponse().getContentAsString()).contains("\"outcome\":\"success\"");

    // -- 3. Start authentication --------------------------------------------------------------
    StartAuthenticationRequest startAuth = new StartAuthenticationRequest("alice", null);
    MvcResult startAuthResult =
        mockMvc
            .perform(
                post("/auth/passkeys/authentication/start")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(startAuth)))
            .andExpect(status().isOk())
            .andReturn();
    StartAuthenticationResponse startAuthResp =
        objectMapper.readValue(
            startAuthResult.getResponse().getContentAsString(), StartAuthenticationResponse.class);

    // -- 4. Finish authentication; verify the minted JWT --------------------------------------
    UserHandle handle = userLookup.findHandleByUsername("alice").orElseThrow();
    AuthenticationResponseJson authResponse =
        authenticator.createAssertionResponse(startAuthResp, handle);
    FinishAuthenticationRequest finishAuth =
        new FinishAuthenticationRequest(startAuthResp.challengeId(), authResponse);
    MvcResult finishAuthResult =
        mockMvc
            .perform(
                post("/auth/passkeys/authentication/finish")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(finishAuth)))
            .andExpect(status().isOk())
            .andReturn();
    String authBody = finishAuthResult.getResponse().getContentAsString();
    assertThat(authBody).contains("\"outcome\":\"success\"");
    // Token is delivered in the response body; the Authorization response-header echo was
    // removed because reverse proxies / access logs can capture it and broaden the leak surface.
    String token = objectMapper.readTree(authBody).path("token").asString();
    assertThat(token).isNotBlank();

    JwtVerificationResult verification = jwtValidator.validate(token);
    assertThat(verification).isInstanceOf(JwtVerificationResult.Success.class);
    JwtVerificationResult.Success ok = (JwtVerificationResult.Success) verification;
    assertThat(ok.claims().userHandle()).isEqualTo(handle);
  }

  @Test
  void invalidRegistrationChallengeReturns400() throws Exception {
    StartRegistrationRequest startReg = new StartRegistrationRequest("bob", null, null, null);
    MvcResult startResult =
        mockMvc
            .perform(
                post("/auth/passkeys/registration/start")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(startReg)))
            .andExpect(status().isOk())
            .andReturn();
    StartRegistrationResponse startResp =
        objectMapper.readValue(
            startResult.getResponse().getContentAsString(), StartRegistrationResponse.class);

    RegistrationResponseJson regResponse = authenticator.createRegistrationResponse(startResp);
    FinishRegistrationRequest finishReg =
        new FinishRegistrationRequest(
            new ChallengeId("00000000-0000-0000-0000-000000000000"), "bob", "ignored", regResponse);

    mockMvc
        .perform(
            post("/auth/passkeys/registration/finish")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(finishReg)))
        .andExpect(status().isBadRequest());
  }
}
