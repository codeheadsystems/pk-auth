// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard;

import com.codeheadsystems.pkauth.admin.AdminService;
import com.codeheadsystems.pkauth.dropwizard.admin.PkAuthAdminResource;
import com.codeheadsystems.pkauth.dropwizard.auth.PkAuthDropwizardAuthFilter;
import com.codeheadsystems.pkauth.dropwizard.auth.PkAuthPasskeyPrincipal;
import com.codeheadsystems.pkauth.dropwizard.dagger.AltFlowsModule;
import com.codeheadsystems.pkauth.dropwizard.dagger.AltFlowsModule.AltFlowOptions;
import com.codeheadsystems.pkauth.dropwizard.dagger.DaggerPkAuthComponent;
import com.codeheadsystems.pkauth.dropwizard.dagger.DaggerPkAuthFullComponent;
import com.codeheadsystems.pkauth.dropwizard.dagger.PersistenceBindings;
import com.codeheadsystems.pkauth.dropwizard.dagger.PkAuthCeremonyGraph;
import com.codeheadsystems.pkauth.dropwizard.dagger.PkAuthComponent;
import com.codeheadsystems.pkauth.dropwizard.dagger.PkAuthFullComponent;
import com.codeheadsystems.pkauth.dropwizard.dagger.PkAuthModule;
import com.codeheadsystems.pkauth.dropwizard.json.PkAuthJacksonBridge;
import com.codeheadsystems.pkauth.dropwizard.resource.PkAuthRefreshResource;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.core.ConfiguredBundle;
import io.dropwizard.core.setup.Bootstrap;
import io.dropwizard.core.setup.Environment;
import java.util.Objects;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Dropwizard bundle that wires pk-auth's ceremony service, JWT issuance, and optional admin
 * endpoints into a host application. Brief §6.11.
 *
 * <p>Wiring is compile-time via Dagger 2 (ADR 0004). The host application supplies:
 *
 * <ol>
 *   <li>A {@code Configuration} class implementing {@link HasPkAuthConfig}.
 *   <li>A {@link PersistenceBindings} describing the SPI implementations (JDBI, DynamoDB, or the
 *       testkit's in-memory variant).
 *   <li>Optional: either a pre-built {@link AdminService} (legacy constructor), or an {@link
 *       AltFlowOptions} bag that lets the bundle build {@link AdminService} internally from the OTP
 *       / magic-link / backup-code blocks of {@link
 *       com.codeheadsystems.pkauth.dropwizard.config.PkAuthConfig}. When the alt-flow constructor
 *       is used the bundle additionally mounts {@link PkAuthAdminResource} at {@code /auth/admin}
 *       without further wiring from the host, matching the Spring and Micronaut adapters.
 * </ol>
 *
 * <p>Dropwizard 5 still wires Jackson 2 internally; pk-auth-core uses Jackson 3 (ADR 0009). The
 * bundle teaches Dropwizard's Jackson 2 {@code ObjectMapper} how to read and write base64url byte
 * arrays and pk-auth's value types; see {@link PkAuthJacksonBridge}. Wire compatibility is verified
 * end-to-end by the integration tests.
 *
 * @param <C> the host application's Configuration type.
 * @since 0.9.1 (alt-flow auto-wiring constructor added; legacy two-arg constructor preserved).
 */
public class PkAuthBundle<C extends HasPkAuthConfig> implements ConfiguredBundle<C> {

  private static final Logger LOG = LoggerFactory.getLogger(PkAuthBundle.class);
  private static final String NOT_RUN = "PkAuthBundle.run has not been invoked yet";

  private final PersistenceBindings persistence;
  private final @Nullable AdminService preBuiltAdminService;
  private final @Nullable AltFlowOptions altFlowOptions;

  /** Either a {@link PkAuthComponent} or a {@link PkAuthFullComponent}; null until {@link #run}. */
  private @Nullable PkAuthCeremonyGraph graph;

  /**
   * Constructs a bundle without admin support. Only the four ceremony endpoints are mounted.
   *
   * @param persistence the SPI implementations used by the ceremony service.
   */
  public PkAuthBundle(PersistenceBindings persistence) {
    this(persistence, (AdminService) null);
  }

  /**
   * Legacy constructor: the host has already hand-built an {@link AdminService} and hands it to the
   * bundle. The bundle mounts the admin resource but does not auto-wire backup-code / magic-link /
   * OTP services itself. The {@link AltFlowOptions} constructor is preferred for new applications.
   *
   * @param persistence the SPI implementations used by the ceremony service.
   * @param adminService the admin service, or null to skip admin endpoint registration.
   */
  public PkAuthBundle(PersistenceBindings persistence, @Nullable AdminService adminService) {
    this.persistence = Objects.requireNonNull(persistence, "persistence");
    this.preBuiltAdminService = adminService;
    this.altFlowOptions = null;
  }

  /**
   * Auto-wiring constructor (mirrors Spring / Micronaut). The bundle builds {@link
   * com.codeheadsystems.pkauth.backupcodes.BackupCodeService}, {@link
   * com.codeheadsystems.pkauth.magiclink.MagicLinkService}, {@link
   * com.codeheadsystems.pkauth.otp.OtpService}, and an {@link AdminService} from the OTP /
   * magic-link / backup-code blocks of {@link
   * com.codeheadsystems.pkauth.dropwizard.config.PkAuthConfig} and the sender beans handed in via
   * {@code altFlowOptions}. The admin resource is mounted at {@code /auth/admin}.
   *
   * <p>The supplied {@link PersistenceBindings} must include {@link
   * PersistenceBindings#backupCodeRepository()} and {@link PersistenceBindings#otpRepository()};
   * construction throws otherwise.
   *
   * @param persistence the SPI implementations used by the ceremony service and alt-flows.
   * @param altFlowOptions host-supplied senders, authoriser, and dev-mode toggles.
   * @since 0.9.1
   */
  public PkAuthBundle(PersistenceBindings persistence, AltFlowOptions altFlowOptions) {
    this.persistence = Objects.requireNonNull(persistence, "persistence");
    this.altFlowOptions = Objects.requireNonNull(altFlowOptions, "altFlowOptions");
    this.preBuiltAdminService = null;
  }

  @Override
  public void initialize(Bootstrap<?> bootstrap) {
    // Brief §6.11 — no additional bootstrap-phase wiring needed; Jersey resources are registered
    // in run(). We do register the Jackson 2 bridge here so any other bundle that reads the
    // ObjectMapper after us sees the pk-auth value-type serializers already installed.
    PkAuthJacksonBridge.register(bootstrap.getObjectMapper());
  }

  @Override
  public void run(C configuration, Environment environment) {
    PkAuthModule pkAuthModule = new PkAuthModule(configuration.pkAuth(), persistence);
    PkAuthCeremonyGraph activeGraph;
    if (altFlowOptions != null) {
      // Auto-wire alt-flows + admin via Dagger. The SPIs that back them must be present.
      BackupCodeRepository backupCodeRepository = persistence.backupCodeRepository();
      if (backupCodeRepository == null) {
        throw new IllegalStateException(
            "PkAuthBundle alt-flow auto-wiring requires PersistenceBindings.backupCodeRepository"
                + " to be non-null.");
      }
      OtpRepository otpRepository = persistence.otpRepository();
      if (otpRepository == null) {
        throw new IllegalStateException(
            "PkAuthBundle alt-flow auto-wiring requires PersistenceBindings.otpRepository to be"
                + " non-null.");
      }
      activeGraph =
          DaggerPkAuthFullComponent.builder()
              .pkAuthModule(pkAuthModule)
              .altFlowsModule(
                  new AltFlowsModule(altFlowOptions, backupCodeRepository, otpRepository))
              .build();
    } else {
      activeGraph = DaggerPkAuthComponent.builder().pkAuthModule(pkAuthModule).build();
    }
    this.graph = activeGraph;

    // Ensure the runtime ObjectMapper has the bridge too (the environment may build its own copy
    // distinct from the bootstrap's).
    PkAuthJacksonBridge.register(environment.getObjectMapper());

    environment.jersey().register(activeGraph.ceremonyResource());
    environment
        .jersey()
        .register(
            new com.codeheadsystems.pkauth.dropwizard.resource.PkAuthPersistenceExceptionMapper());

    environment
        .jersey()
        .register(
            new AuthDynamicFeature(
                PkAuthDropwizardAuthFilter.build(activeGraph.passkeyAuthenticator())));
    environment
        .jersey()
        .register(new AuthValueFactoryProvider.Binder<>(PkAuthPasskeyPrincipal.class));

    if (activeGraph instanceof PkAuthFullComponent fullComponent) {
      environment.jersey().register(fullComponent.adminResource());
      LOG.info("pkauth.admin.endpoints.registered path=/auth/admin (auto-wired alt-flows + admin)");
    } else if (preBuiltAdminService != null) {
      environment.jersey().register(new PkAuthAdminResource(preBuiltAdminService));
      LOG.info("pkauth.admin.endpoints.registered path=/auth/admin (host-built AdminService)");
    }

    activeGraph
        .refreshHandler()
        .ifPresent(
            handler -> {
              environment.jersey().register(new PkAuthRefreshResource(handler));
              LOG.info("pkauth.refresh.endpoint.registered path=/auth/refresh");
            });

    LOG.info(
        "pkauth.bundle.started rp={} issuer={}",
        configuration.pkAuth().relyingParty().id(),
        configuration.pkAuth().jwt().issuer());
  }

  /**
   * Returns the constructed slim Dagger component. Available after {@link #run} has executed when
   * the bundle was built without {@link AltFlowOptions}. When the alt-flow constructor was used,
   * call {@link #fullComponent()} instead.
   */
  public PkAuthComponent component() {
    if (graph instanceof PkAuthComponent component) {
      return component;
    }
    if (graph instanceof PkAuthFullComponent) {
      throw new IllegalStateException(
          "PkAuthBundle is running with alt-flow auto-wiring; call fullComponent() instead of"
              + " component().");
    }
    throw new IllegalStateException(NOT_RUN);
  }

  /**
   * Returns the constructed full Dagger component (ceremony + alt-flows + admin). Available after
   * {@link #run} has executed when the bundle was built with the {@link AltFlowOptions}
   * constructor.
   *
   * @since 0.9.1
   */
  public PkAuthFullComponent fullComponent() {
    if (graph instanceof PkAuthFullComponent fullComponent) {
      return fullComponent;
    }
    throw new IllegalStateException(
        "PkAuthBundle was not registered with alt-flow auto-wiring (AltFlowOptions). Use"
            + " component() or register the bundle with the alt-flow constructor.");
  }

  /** Convenience for tests / integrators that need the JWT issuer after the app has started. */
  public PkAuthJwtIssuer jwtIssuer() {
    return ceremonyGraph().jwtIssuer();
  }

  /** Convenience for tests / integrators that need the JWT validator after the app has started. */
  public PkAuthJwtValidator jwtValidator() {
    return ceremonyGraph().jwtValidator();
  }

  private PkAuthCeremonyGraph ceremonyGraph() {
    if (graph == null) {
      throw new IllegalStateException(NOT_RUN);
    }
    return graph;
  }
}
