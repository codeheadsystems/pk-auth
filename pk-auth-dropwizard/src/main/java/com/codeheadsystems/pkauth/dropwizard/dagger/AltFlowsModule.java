// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.dagger;

import com.codeheadsystems.pkauth.admin.AdminAuthorizer;
import com.codeheadsystems.pkauth.admin.AdminSafetyConfig;
import com.codeheadsystems.pkauth.admin.AdminService;
import com.codeheadsystems.pkauth.admin.DefaultAdminService;
import com.codeheadsystems.pkauth.backupcodes.BackupCodeService;
import com.codeheadsystems.pkauth.dropwizard.admin.PkAuthAdminResource;
import com.codeheadsystems.pkauth.dropwizard.config.PkAuthConfig;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.lifecycle.BackupCodeRepositoryDeletionListener;
import com.codeheadsystems.pkauth.lifecycle.OtpRepositoryDeletionListener;
import com.codeheadsystems.pkauth.lifecycle.UserDeletionListener;
import com.codeheadsystems.pkauth.magiclink.EmailSender;
import com.codeheadsystems.pkauth.magiclink.LoggingEmailSender;
import com.codeheadsystems.pkauth.magiclink.MagicLinkService;
import com.codeheadsystems.pkauth.otp.LoggingSmsSender;
import com.codeheadsystems.pkauth.otp.OtpService;
import com.codeheadsystems.pkauth.otp.SmsSender;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;
import dagger.Module;
import dagger.Provides;
import dagger.multibindings.IntoSet;
import jakarta.inject.Singleton;
import java.util.Objects;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Dagger module that auto-wires the alt-flow services (backup-codes, magic-link, OTP) and a {@link
 * DefaultAdminService} so a Dropwizard host can mount {@link PkAuthAdminResource} without
 * hand-building the dependency graph.
 *
 * <p>Mirrors the Spring {@code PkAuthAutoConfiguration} and Micronaut {@code PkAuthFactory}
 * provider sets so the three adapters expose the same admin endpoint surface from the same
 * configuration shape. This module is used only by {@link PkAuthFullComponent}; the slim {@link
 * PkAuthComponent} (passkey-ceremony-only) does not include it.
 *
 * <p>Fail-fast policy: no adapter-level defaults. The host must hand in the OTP pepper, the
 * magic-link base URL, and an explicit {@link EmailSender} / {@link SmsSender} (or accept the
 * {@link LoggingEmailSender} / {@link LoggingSmsSender} dev-only fallback by passing {@code null}
 * senders, which only activates when the {@link AltFlowOptions#devMode()} flag is true).
 *
 * @since 0.9.1
 */
@Module
public final class AltFlowsModule {

  private static final Logger LOG = LoggerFactory.getLogger(AltFlowsModule.class);

  private final AltFlowOptions options;
  private final BackupCodeRepository backupCodeRepository;
  private final OtpRepository otpRepository;

  /**
   * Constructs the alt-flows module. All three persistence collaborators must be non-null; an
   * {@link IllegalStateException} is raised at module construction time when the bundle was
   * registered with alt-flow auto-wiring but the {@link PersistenceBindings} omitted them.
   *
   * @param options host-supplied alt-flow knobs (senders, authorizer, dev-mode flag).
   * @param backupCodeRepository backup-code SPI; required.
   * @param otpRepository OTP SPI; required.
   * @since 0.9.1
   */
  public AltFlowsModule(
      AltFlowOptions options,
      BackupCodeRepository backupCodeRepository,
      OtpRepository otpRepository) {
    this.options = Objects.requireNonNull(options, "options");
    this.backupCodeRepository =
        Objects.requireNonNull(
            backupCodeRepository,
            "backupCodeRepository must be supplied when alt-flow auto-wiring is enabled");
    this.otpRepository =
        Objects.requireNonNull(
            otpRepository, "otpRepository must be supplied when alt-flow auto-wiring is enabled");
  }

  @Provides
  @Singleton
  AltFlowOptions provideOptions() {
    return options;
  }

  @Provides
  @Singleton
  BackupCodeRepository provideBackupCodeRepository() {
    return backupCodeRepository;
  }

  @Provides
  @Singleton
  OtpRepository provideOtpRepository() {
    return otpRepository;
  }

  /**
   * Resolves an {@link EmailSender}. Host-supplied wins; otherwise the dev-mode opt-in surfaces a
   * {@link LoggingEmailSender} with a loud startup warning. Without either, fails fast.
   */
  @Provides
  @Singleton
  EmailSender provideEmailSender(AltFlowOptions opts) {
    EmailSender supplied = opts.emailSender();
    if (supplied != null) {
      return supplied;
    }
    if (opts.devMode()) {
      LOG.error(
          "pkauth dev-mode enabled: using LoggingEmailSender — magic-link tokens will be written"
              + " to the application log. DO NOT use in production.");
      return new LoggingEmailSender();
    }
    throw new IllegalStateException(
        "No EmailSender supplied to PkAuthBundle alt-flow wiring. Hand the bundle a real"
            + " EmailSender via AltFlowOptions or enable dev-mode for the LoggingEmailSender"
            + " fallback (dev only).");
  }

  /**
   * Resolves an {@link SmsSender}. Same fail-fast policy as {@link #provideEmailSender}: host wins,
   * dev-mode unlocks the logging fallback, otherwise startup fails.
   */
  @Provides
  @Singleton
  SmsSender provideSmsSender(AltFlowOptions opts) {
    SmsSender supplied = opts.smsSender();
    if (supplied != null) {
      return supplied;
    }
    if (opts.devMode()) {
      LOG.error(
          "pkauth dev-mode enabled: using LoggingSmsSender — OTP codes will be written to the"
              + " application log. DO NOT use in production.");
      return new LoggingSmsSender();
    }
    throw new IllegalStateException(
        "No SmsSender supplied to PkAuthBundle alt-flow wiring. Hand the bundle a real SmsSender"
            + " via AltFlowOptions or enable dev-mode for the LoggingSmsSender fallback (dev"
            + " only).");
  }

  @Provides
  @Singleton
  BackupCodeService provideBackupCodeService(BackupCodeRepository repo, ClockProvider clock) {
    return BackupCodeService.create(BackupCodeService.Dependencies.of(repo, clock));
  }

  @Provides
  @Singleton
  MagicLinkService provideMagicLinkService(
      PkAuthJwtIssuer issuer,
      PkAuthJwtValidator validator,
      EmailSender emailSender,
      UserLookup userLookup,
      ClockProvider clock,
      PkAuthConfig cfg) {
    PkAuthConfig.MagicLink ml = cfg.magicLink();
    if (ml == null) {
      throw new IllegalStateException(
          "pkAuth.magicLink configuration block is required when alt-flow auto-wiring is enabled"
              + " (set magicLink.baseUrl).");
    }
    return MagicLinkService.create(
        MagicLinkService.Dependencies.of(issuer, validator, emailSender, userLookup, clock),
        ml.baseUrl());
  }

  @Provides
  @Singleton
  OtpService provideOtpService(
      OtpRepository repo, SmsSender smsSender, ClockProvider clock, PkAuthConfig cfg) {
    PkAuthConfig.Otp otp = cfg.otp();
    if (otp == null) {
      throw new IllegalStateException(
          "pkAuth.otp configuration block is required when alt-flow auto-wiring is enabled (set"
              + " otp.pepper to ≥ 16 bytes of cryptographic randomness).");
    }
    return OtpService.create(OtpService.Dependencies.of(repo, smsSender, clock), otp.pepper());
  }

  @Provides
  @Singleton
  AdminService provideAdminService(
      CredentialRepository credentialRepository,
      UserLookup userLookup,
      BackupCodeService backupCodeService,
      MagicLinkService magicLinkService,
      OtpService otpService,
      AltFlowOptions opts) {
    AdminAuthorizer authorizer = opts.adminAuthorizer();
    AdminSafetyConfig safety = opts.adminSafetyConfig();
    DefaultAdminService.Dependencies deps =
        new DefaultAdminService.Dependencies(
            credentialRepository, userLookup, backupCodeService, magicLinkService, otpService);
    DefaultAdminService.Config config =
        new DefaultAdminService.Config(
            authorizer != null ? authorizer : AdminAuthorizer.subjectScoped(),
            safety != null ? safety : AdminSafetyConfig.defaults());
    return DefaultAdminService.create(deps, config);
  }

  @Provides
  @Singleton
  PkAuthAdminResource provideAdminResource(AdminService adminService) {
    return new PkAuthAdminResource(adminService);
  }

  /** User-deletion listener for backup codes — only present in the full component. */
  @Provides
  @Singleton
  @IntoSet
  UserDeletionListener provideBackupCodeDeletionListener(BackupCodeRepository repo) {
    return new BackupCodeRepositoryDeletionListener(repo);
  }

  /** User-deletion listener for OTPs — only present in the full component. */
  @Provides
  @Singleton
  @IntoSet
  UserDeletionListener provideOtpDeletionListener(OtpRepository repo) {
    return new OtpRepositoryDeletionListener(repo);
  }

  /**
   * Host-supplied tunables that do not live in {@link PkAuthConfig} (they're framework-level
   * collaborators, not YAML-bindable values).
   *
   * @param emailSender concrete {@link EmailSender}; null + {@code devMode=true} unlocks {@link
   *     LoggingEmailSender}, null + {@code devMode=false} fails fast at startup.
   * @param smsSender concrete {@link SmsSender}; same fail-fast policy as {@code emailSender}.
   * @param adminAuthorizer {@link DefaultAdminService} authorizer; null uses the library default
   *     ({@link AdminAuthorizer#subjectScoped()}).
   * @param adminSafetyConfig {@link DefaultAdminService} safety config; null uses {@link
   *     AdminSafetyConfig#defaults()}.
   * @param devMode when true, missing senders fall back to logging implementations. Production
   *     deploys must leave this false.
   * @since 0.9.1
   */
  public record AltFlowOptions(
      @Nullable EmailSender emailSender,
      @Nullable SmsSender smsSender,
      @Nullable AdminAuthorizer adminAuthorizer,
      @Nullable AdminSafetyConfig adminSafetyConfig,
      boolean devMode) {

    /** Returns a builder pre-populated with {@code devMode=false} and no overrides. */
    public static Builder builder() {
      return new Builder();
    }

    /** Mutable builder for {@link AltFlowOptions}. */
    public static final class Builder {
      private @Nullable EmailSender emailSender;
      private @Nullable SmsSender smsSender;
      private @Nullable AdminAuthorizer adminAuthorizer;
      private @Nullable AdminSafetyConfig adminSafetyConfig;
      private boolean devMode;

      private Builder() {}

      public Builder emailSender(@Nullable EmailSender v) {
        this.emailSender = v;
        return this;
      }

      public Builder smsSender(@Nullable SmsSender v) {
        this.smsSender = v;
        return this;
      }

      public Builder adminAuthorizer(@Nullable AdminAuthorizer v) {
        this.adminAuthorizer = v;
        return this;
      }

      public Builder adminSafetyConfig(@Nullable AdminSafetyConfig v) {
        this.adminSafetyConfig = v;
        return this;
      }

      public Builder devMode(boolean v) {
        this.devMode = v;
        return this;
      }

      public AltFlowOptions build() {
        return new AltFlowOptions(
            emailSender, smsSender, adminAuthorizer, adminSafetyConfig, devMode);
      }
    }
  }
}
