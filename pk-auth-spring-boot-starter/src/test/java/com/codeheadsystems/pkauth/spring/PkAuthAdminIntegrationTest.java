// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.codeheadsystems.pkauth.api.AuthenticationResponseJson;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResponse;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResponse;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.codeheadsystems.pkauth.testkit.FakeAuthenticator;
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import tools.jackson.databind.ObjectMapper;

/** Exercises a couple of admin endpoints behind the JWT filter using a real JWT. */
@SpringBootTest(classes = PkAuthTestApplication.class)
class PkAuthAdminIntegrationTest {

  @Autowired private WebApplicationContext webApplicationContext;
  @Autowired private ObjectMapper objectMapper;
  @Autowired private UserLookup userLookup;
  @Autowired private RelyingPartyConfig relyingParty;
  @Autowired private com.codeheadsystems.pkauth.spi.CeremonyRateLimiter ceremonyRateLimiter;

  private MockMvc mockMvc;
  private FakeAuthenticator authenticator;

  @BeforeEach
  void setUp() {
    // The in-memory ceremony rate limiter is a shared singleton across this class's reused
    // context; without a per-test reset the cumulative start/finish calls trip the per-IP limit.
    if (ceremonyRateLimiter
        instanceof com.codeheadsystems.pkauth.ceremony.InMemoryCeremonyRateLimiter inMemory) {
      inMemory.reset();
    }
    mockMvc =
        MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .apply(SecurityMockMvcConfigurers.springSecurity())
            .build();
    authenticator =
        FakeAuthenticator.builder()
            .origin(relyingParty.origins().iterator().next())
            .rpId(relyingParty.id())
            .objectConverter(new ObjectConverter())
            .build();
  }

  @Test
  void unauthenticatedAdminCallIsRejected() throws Exception {
    mockMvc.perform(get("/auth/admin/account")).andExpect(status().isUnauthorized());
  }

  @Test
  void authenticatedListCredentialsReturnsTheUserPasskey() throws Exception {
    String token = registerAndLogin("carol");

    mockMvc
        .perform(get("/auth/admin/credentials").header("Authorization", "Bearer " + token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].label").value("Carol Key"));
  }

  @Test
  void authenticatedRegenerateBackupCodesReturnsCodesOnce() throws Exception {
    String token = registerAndLogin("dave");

    mockMvc
        .perform(
            post("/auth/admin/backup-codes/regenerate").header("Authorization", "Bearer " + token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.codes").isArray())
        .andExpect(jsonPath("$.codes.length()").value(10));

    mockMvc
        .perform(get("/auth/admin/backup-codes/count").header("Authorization", "Bearer " + token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.remaining").value(10));
  }

  @Test
  void authenticatedAccountSummaryIncludesUsername() throws Exception {
    String token = registerAndLogin("erin");
    mockMvc
        .perform(get("/auth/admin/account").header("Authorization", "Bearer " + token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.username").value("erin"));
  }

  @Test
  void authenticatedRenameCredentialUpdatesLabel() throws Exception {
    String token = registerAndLogin("frank");
    // discover the credential id via list
    MvcResult list =
        mockMvc
            .perform(get("/auth/admin/credentials").header("Authorization", "Bearer " + token))
            .andReturn();
    String body = list.getResponse().getContentAsString();
    int idStart = body.indexOf("\"credentialId\":\"") + "\"credentialId\":\"".length();
    int idEnd = body.indexOf('"', idStart);
    String credentialId = body.substring(idStart, idEnd);

    mockMvc
        .perform(
            patch("/auth/admin/credentials/" + credentialId)
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"label\":\"Renamed\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.label").value("Renamed"));
  }

  @Test
  void startEmailVerificationReturns204() throws Exception {
    String token = registerAndLogin("gina");
    mockMvc
        .perform(
            post("/auth/admin/email/start-verification")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"gina@example.com\"}"))
        .andExpect(status().isNoContent());
  }

  @Test
  void startPhoneVerificationReturnsOtpId() throws Exception {
    String token = registerAndLogin("henry");
    mockMvc
        .perform(
            post("/auth/admin/phone/start-verification")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"phone\":\"+15551234567\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.otpId").exists());
  }

  @Test
  void finishEmailVerificationWithBlankTokenReturns400() throws Exception {
    mockMvc
        .perform(
            post("/auth/admin/email/complete-verification")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"token\":\"\"}"))
        .andExpect(status().isBadRequest());
  }

  @Test
  void authenticatedDeleteCredentialRemovesIt() throws Exception {
    String token = registerAndLogin("ivan");
    // Deleting the last credential is refused (409) unless backup codes remain — generate them
    // first so the delete reaches its success path.
    mockMvc
        .perform(
            post("/auth/admin/backup-codes/regenerate").header("Authorization", "Bearer " + token))
        .andExpect(status().isOk());
    MvcResult list =
        mockMvc
            .perform(get("/auth/admin/credentials").header("Authorization", "Bearer " + token))
            .andReturn();
    String body = list.getResponse().getContentAsString();
    int idStart = body.indexOf("\"credentialId\":\"") + "\"credentialId\":\"".length();
    int idEnd = body.indexOf('"', idStart);
    String credentialId = body.substring(idStart, idEnd);

    mockMvc
        .perform(
            delete("/auth/admin/credentials/" + credentialId)
                .header("Authorization", "Bearer " + token))
        .andExpect(status().isNoContent());

    // The credential list is now empty.
    mockMvc
        .perform(get("/auth/admin/credentials").header("Authorization", "Bearer " + token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.length()").value(0));
  }

  @Test
  void finishPhoneVerificationAfterStartReturnsResult() throws Exception {
    String token = registerAndLogin("judy");
    mockMvc
        .perform(
            post("/auth/admin/phone/start-verification")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"phone\":\"+15557654321\"}"))
        .andExpect(status().isOk());
    // Complete with a (near-certainly) wrong code: the handler runs and maps the typed result to
    // a 200 body regardless of match/mismatch.
    mockMvc
        .perform(
            post("/auth/admin/phone/complete-verification")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"phone\":\"+15557654321\",\"code\":\"000000\"}"))
        .andExpect(status().isOk());
  }

  private String registerAndLogin(String username) throws Exception {
    // register
    StartRegistrationRequest sr = new StartRegistrationRequest(username, username, null, null);
    MvcResult startReg =
        mockMvc
            .perform(
                post("/auth/passkeys/registration/start")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(sr)))
            .andReturn();
    StartRegistrationResponse startRegResp =
        objectMapper.readValue(
            startReg.getResponse().getContentAsString(), StartRegistrationResponse.class);
    RegistrationResponseJson regResponse = authenticator.createRegistrationResponse(startRegResp);
    String label =
        username.substring(0, 1).toUpperCase(java.util.Locale.ROOT)
            + username.substring(1)
            + " Key";
    FinishRegistrationRequest fr =
        new FinishRegistrationRequest(startRegResp.challengeId(), username, label, regResponse);
    mockMvc
        .perform(
            post("/auth/passkeys/registration/finish")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(fr)))
        .andExpect(status().isOk());

    // login
    StartAuthenticationRequest sa = new StartAuthenticationRequest(username, null);
    MvcResult startAuth =
        mockMvc
            .perform(
                post("/auth/passkeys/authentication/start")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(sa)))
            .andReturn();
    StartAuthenticationResponse startAuthResp =
        objectMapper.readValue(
            startAuth.getResponse().getContentAsString(), StartAuthenticationResponse.class);
    UserHandle handle = userLookup.findHandleByUsername(username).orElseThrow();
    AuthenticationResponseJson authResponse =
        authenticator.createAssertionResponse(startAuthResp, handle);
    FinishAuthenticationRequest fa =
        new FinishAuthenticationRequest(startAuthResp.challengeId(), authResponse);
    MvcResult authResult =
        mockMvc
            .perform(
                post("/auth/passkeys/authentication/finish")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(fa)))
            .andExpect(status().isOk())
            .andReturn();
    String body = authResult.getResponse().getContentAsString();
    String token = objectMapper.readTree(body).path("token").asString();
    assertThat(token).isNotBlank();
    return token;
  }
}
