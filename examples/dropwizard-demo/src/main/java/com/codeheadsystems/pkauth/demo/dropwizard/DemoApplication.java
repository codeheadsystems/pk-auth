// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.demo.dropwizard;

import com.codeheadsystems.pkauth.admin.AdminAuthorizer;
import com.codeheadsystems.pkauth.dropwizard.PkAuthBundle;
import com.codeheadsystems.pkauth.dropwizard.dagger.AltFlowsModule.AltFlowOptions;
import com.codeheadsystems.pkauth.dropwizard.dagger.PersistenceBindings;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryBackupCodeRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryChallengeStore;
import com.codeheadsystems.pkauth.testkit.InMemoryCredentialRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryOtpRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryUserLookup;
import io.dropwizard.assets.AssetsBundle;
import io.dropwizard.core.Application;
import io.dropwizard.core.setup.Bootstrap;
import io.dropwizard.core.setup.Environment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Single-page Dropwizard demo for pk-auth. The persistence flavour is read from the {@code
 * PKAUTH_PERSISTENCE} environment variable, then from the {@code pkauth.persistence} system
 * property, and defaults to {@code memory}. Every flavour, including {@code jdbi} and {@code
 * dynamodb}, currently routes to the testkit's in-memory SPIs, so the demo runs without external
 * services. Real JDBI and DynamoDB wiring awaits a higher-level {@code build()} factory in those
 * modules.
 *
 * <p>The demo uses {@link PkAuthBundle}'s alt-flow auto-wiring constructor, and the bundle
 * internally builds the backup-code, magic-link, OTP, and admin services from the YAML config plus
 * the senders handed in via {@link AltFlowOptions}. The bundle performs this wiring once, shared
 * across the three adapters, so the demo carries no hand-wiring.
 */
public final class DemoApplication extends Application<DemoConfiguration> {

  private static final Logger LOG = LoggerFactory.getLogger(DemoApplication.class);

  /** Entry point for {@code ./gradlew :examples:dropwizard-demo:run}. */
  public static void main(String[] args) throws Exception {
    new DemoApplication().run(args.length == 0 ? new String[] {"server"} : args);
  }

  @Override
  public String getName() {
    return "pk-auth-dropwizard-demo";
  }

  @Override
  public void initialize(Bootstrap<DemoConfiguration> bootstrap) {
    // Mount the SPA under /ui/* to avoid the AssetsBundle clashing with Jersey at /*; the
    // application root redirects to /ui/ via a servlet filter in run().
    bootstrap.addBundle(new AssetsBundle("/assets", "/ui", "index.html", "assets"));

    DemoPersistence persistence = DemoPersistence.create(persistenceFlavor());
    AltFlowOptions altFlowOptions =
        AltFlowOptions.builder()
            // No senders supplied — the demo runs in dev-mode so the bundle drops in the
            // LoggingEmailSender / LoggingSmsSender shims and yells about it in the log.
            .devMode(true)
            .adminAuthorizer(AdminAuthorizer.subjectScoped())
            .build();
    PkAuthBundle<DemoConfiguration> pkAuth =
        new PkAuthBundle<>(persistence.bindings(), altFlowOptions);
    bootstrap.addBundle(pkAuth);
  }

  @Override
  public void run(DemoConfiguration configuration, Environment environment) {
    LOG.info("Demo server starting at http://localhost:8080/ui/");
    LOG.info("Persistence flavor: {}", persistenceFlavor());
    // Tiny redirect servlet so http://localhost:8080/ lands on the SPA.
    environment
        .servlets()
        .addServlet(
            "root-redirect",
            new jakarta.servlet.http.HttpServlet() {
              @Override
              protected void doGet(
                  jakarta.servlet.http.HttpServletRequest req,
                  jakarta.servlet.http.HttpServletResponse resp)
                  throws java.io.IOException {
                if ("/".equals(req.getRequestURI())) {
                  resp.sendRedirect("/ui/");
                } else {
                  resp.sendError(404);
                }
              }
            })
        .addMapping("");
  }

  private String persistenceFlavor() {
    String env = System.getenv("PKAUTH_PERSISTENCE");
    if (env != null && !env.isBlank()) {
      return env;
    }
    String prop = System.getProperty("pkauth.persistence");
    return prop == null ? "memory" : prop;
  }

  /**
   * Small holder bundling the bound SPIs so the demo can hand them to the bundle without
   * re-instantiating in-memory state.
   */
  static final class DemoPersistence {
    private final PersistenceBindings bindings;
    private final InMemoryUserLookup userLookup;

    private DemoPersistence(PersistenceBindings bindings, InMemoryUserLookup userLookup) {
      this.bindings = bindings;
      this.userLookup = userLookup;
    }

    PersistenceBindings bindings() {
      return bindings;
    }

    InMemoryUserLookup userLookup() {
      return userLookup;
    }

    static DemoPersistence create(String flavor) {
      // The brief calls for jdbi/dynamodb flavors. v0.x routes both to the testkit's in-memory
      // SPIs so the demo runs without external services. Real Postgres / DynamoDB wiring lands
      // alongside the JDBI/DDB module's "all-in-one" factories (Phase 12 polish).
      LOG.info("Using {} (in-memory backing for v0.x)", flavor);
      InMemoryCredentialRepository credentials = new InMemoryCredentialRepository();
      InMemoryUserLookup users = new InMemoryUserLookup();
      InMemoryChallengeStore challenges = new InMemoryChallengeStore();
      BackupCodeRepository backupCodes = new InMemoryBackupCodeRepository();
      OtpRepository otps = new InMemoryOtpRepository();
      return new DemoPersistence(
          PersistenceBindings.builder()
              .credentialRepository(credentials)
              .userLookup(users)
              .challengeStore(challenges)
              .backupCodeRepository(backupCodes)
              .otpRepository(otps)
              .build(),
          users);
    }
  }
}
