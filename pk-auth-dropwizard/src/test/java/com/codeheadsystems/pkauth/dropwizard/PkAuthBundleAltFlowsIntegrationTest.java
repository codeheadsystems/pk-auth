// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.admin.AdminAuthorizer;
import com.codeheadsystems.pkauth.dropwizard.config.PkAuthConfig;
import com.codeheadsystems.pkauth.dropwizard.dagger.AltFlowsModule.AltFlowOptions;
import com.codeheadsystems.pkauth.dropwizard.dagger.PersistenceBindings;
import com.codeheadsystems.pkauth.dropwizard.json.PkAuthJacksonBridge;
import com.codeheadsystems.pkauth.testkit.InMemoryBackupCodeRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryEverything;
import com.codeheadsystems.pkauth.testkit.InMemoryOtpRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.jakarta.rs.json.JacksonJsonProvider;
import io.dropwizard.core.Application;
import io.dropwizard.core.setup.Bootstrap;
import io.dropwizard.core.setup.Environment;
import io.dropwizard.testing.junit5.DropwizardAppExtension;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Integration test for {@link PkAuthBundle}'s alt-flow auto-wiring constructor. Asserts that the
 * bundle builds the alt-flow services and admin resource entirely from {@link PkAuthConfig} +
 * {@link AltFlowOptions} — the host has zero hand-wiring code.
 */
@ExtendWith(DropwizardExtensionsSupport.class)
final class PkAuthBundleAltFlowsIntegrationTest {

  /** Local state holder so the test can introspect what the bundle wired. */
  public static final class AutoState {
    public final InMemoryEverything everything = InMemoryEverything.defaults();
    public final InMemoryBackupCodeRepository backupCodes = new InMemoryBackupCodeRepository();
    public final InMemoryOtpRepository otps = new InMemoryOtpRepository();
    public PkAuthBundle<TestConfiguration> bundle;
  }

  /** Active state visible to {@link AutoWireApp}'s no-arg constructor. */
  public static final ThreadLocal<AutoState> ACTIVE = new ThreadLocal<>();

  /** Test-only application that registers {@link PkAuthBundle} with auto-wired alt-flows. */
  public static final class AutoWireApp extends Application<TestConfiguration> {
    private final AutoState state;

    public AutoWireApp() {
      AutoState current = ACTIVE.get();
      if (current == null) {
        current = new AutoState();
        ACTIVE.set(current);
      }
      this.state = current;
    }

    @Override
    public String getName() {
      return "pk-auth-dropwizard-altflows-test";
    }

    @Override
    public void initialize(Bootstrap<TestConfiguration> bootstrap) {
      PersistenceBindings persistence =
          PersistenceBindings.builder()
              .credentialRepository(state.everything.credentials)
              .userLookup(state.everything.users)
              .challengeStore(state.everything.challenges)
              .backupCodeRepository(state.backupCodes)
              .otpRepository(state.otps)
              .build();
      AltFlowOptions options =
          AltFlowOptions.builder()
              .devMode(true)
              .adminAuthorizer(AdminAuthorizer.subjectScoped())
              .build();
      state.bundle = new PkAuthBundle<>(persistence, options);
      bootstrap.addBundle(state.bundle);
    }

    @Override
    public void run(TestConfiguration configuration, Environment environment) {
      // Bundle does the registration.
    }
  }

  private static final byte[] HS256_SECRET = new byte[32];
  private static final byte[] OTP_PEPPER = new byte[32];

  static {
    for (int i = 0; i < 32; i++) {
      HS256_SECRET[i] = (byte) (i + 1);
      OTP_PEPPER[i] = (byte) ((i * 31 + 7) & 0xff);
    }
  }

  private final AutoState state;

  {
    state = new AutoState();
    ACTIVE.set(state);
  }

  private final DropwizardAppExtension<TestConfiguration> app =
      new DropwizardAppExtension<>(
          AutoWireApp.class,
          new TestConfiguration(
              new PkAuthConfig(
                  new PkAuthConfig.RelyingParty(
                      "example.com", "pk-auth test", Set.of("https://example.com")),
                  new PkAuthConfig.Jwt("https://issuer.example", "demo-aud", HS256_SECRET, null),
                  new PkAuthConfig.Ceremony(),
                  new PkAuthConfig.Otp(OTP_PEPPER),
                  new PkAuthConfig.MagicLink("https://example.com"),
                  new PkAuthConfig.BackupCode())));

  private Client client;
  private String baseUrl;

  @BeforeEach
  void setUp() {
    ObjectMapper mapper = PkAuthJacksonBridge.register(app.getObjectMapper().copy());
    client = ClientBuilder.newBuilder().register(new JacksonJsonProvider(mapper)).build();
    baseUrl = "http://localhost:" + app.getLocalPort();
  }

  @AfterEach
  void tearDown() {
    if (client != null) {
      client.close();
      client = null;
    }
    ACTIVE.remove();
  }

  @Test
  void fullComponentExposesAltFlowServices() {
    assertThat(state.bundle.fullComponent()).isNotNull();
    assertThat(state.bundle.fullComponent().backupCodeService()).isNotNull();
    assertThat(state.bundle.fullComponent().magicLinkService()).isNotNull();
    assertThat(state.bundle.fullComponent().otpService()).isNotNull();
    assertThat(state.bundle.fullComponent().adminService()).isNotNull();
    assertThat(state.bundle.fullComponent().adminResource()).isNotNull();
  }

  @Test
  void adminEndpointMountedByAutoWiring() {
    Response r =
        client.target(baseUrl + "/auth/admin/account").request(MediaType.APPLICATION_JSON).get();
    // No bearer ⇒ 401, which proves the admin filter chain is on. Hand-wired wiring would 404.
    assertThat(r.getStatus()).isEqualTo(401);
  }

  @Test
  void legacyComponentMethodThrowsWhenAutoWiringActive() {
    assertThatThrownBy(() -> state.bundle.component())
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("alt-flow auto-wiring");
  }

  @Test
  void jwtAccessorsWorkUnderAutoWiring() {
    assertThat(state.bundle.jwtIssuer()).isNotNull();
    assertThat(state.bundle.jwtValidator()).isNotNull();
  }

  // -- Authenticated admin endpoints (exercise every PkAuthAdminResource handler) -----------

  private String bearerFor(String username) {
    com.codeheadsystems.pkauth.api.UserHandle uh =
        state.everything.users.getOrCreateHandle(username);
    return state
        .bundle
        .jwtIssuer()
        .issue(com.codeheadsystems.pkauth.jwt.JwtClaims.forBackupCode(uh, java.util.List.of("t")));
  }

  private jakarta.ws.rs.client.Invocation.Builder authed(String path, String username) {
    return client
        .target(baseUrl + path)
        .request(MediaType.APPLICATION_JSON)
        .header("Authorization", "Bearer " + bearerFor(username));
  }

  @Test
  void listCredentialsReturnsOkForAuthenticatedUser() {
    try (Response r = authed("/auth/admin/credentials", "dw-list").get()) {
      assertThat(r.getStatus()).isEqualTo(200);
    }
  }

  @Test
  void remainingBackupCodesCountReturnsOk() {
    try (Response r = authed("/auth/admin/backup-codes/count", "dw-count").get()) {
      assertThat(r.getStatus()).isEqualTo(200);
    }
  }

  @Test
  void regenerateBackupCodesReturnsOk() {
    try (Response r =
        authed("/auth/admin/backup-codes/regenerate", "dw-regen")
            .post(jakarta.ws.rs.client.Entity.json("{}"))) {
      assertThat(r.getStatus()).isEqualTo(200);
    }
  }

  @Test
  void deleteUnknownCredentialReturnsNotFound() {
    String id = com.codeheadsystems.pkauth.json.Base64Url.encode(new byte[] {4, 5, 6});
    try (Response r = authed("/auth/admin/credentials/" + id, "dw-del").delete()) {
      assertThat(r.getStatus()).isEqualTo(404);
    }
  }

  @Test
  void startEmailVerificationReturnsNoContent() {
    try (Response r =
        authed("/auth/admin/email/start-verification", "dw-email")
            .post(jakarta.ws.rs.client.Entity.json("{\"email\":\"a@example.com\"}"))) {
      assertThat(r.getStatus()).isEqualTo(204);
    }
  }

  @Test
  void finishEmailVerificationUnauthenticatedRejectsBadToken() {
    try (Response r =
        client
            .target(baseUrl + "/auth/admin/email/complete-verification")
            .request(MediaType.APPLICATION_JSON)
            .post(jakarta.ws.rs.client.Entity.json("{\"token\":\"not.a.jwt\"}"))) {
      assertThat(r.getStatus()).isEqualTo(400);
    }
  }

  @Test
  void startPhoneVerificationReturnsOk() {
    try (Response r =
        authed("/auth/admin/phone/start-verification", "dw-phone")
            .post(jakarta.ws.rs.client.Entity.json("{\"phone\":\"+15551230000\"}"))) {
      assertThat(r.getStatus()).isEqualTo(200);
    }
  }

  @Test
  void finishPhoneVerificationWithNoActiveOtpReturnsOk() {
    try (Response r =
        authed("/auth/admin/phone/complete-verification", "dw-phone-finish")
            .post(
                jakarta.ws.rs.client.Entity.json(
                    "{\"phone\":\"+15559990000\",\"code\":\"000000\"}"))) {
      assertThat(r.getStatus()).isEqualTo(200);
    }
  }
}
