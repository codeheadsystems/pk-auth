// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.backupcodes.BackupCodeService;
import com.codeheadsystems.pkauth.credential.CredentialAlgorithms;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.magiclink.MagicLinkService;
import com.codeheadsystems.pkauth.magiclink.MagicLinkService.ConsumeResult;
import com.codeheadsystems.pkauth.magiclink.MagicLinkService.SendResult;
import com.codeheadsystems.pkauth.otp.OtpService;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default {@link AdminService} composition over the Phase 5/6 SPIs and services.
 *
 * @since 0.9.0
 */
public final class DefaultAdminService implements AdminService {

  private static final Logger LOG = LoggerFactory.getLogger(DefaultAdminService.class);

  private final CredentialRepository credentialRepository;
  private final UserLookup userLookup;
  private final @Nullable BackupCodeService backupCodeService;
  private final @Nullable MagicLinkService magicLinkService;
  private final @Nullable OtpService otpService;
  private final AdminAuthorizer authorizer;
  private final AdminSafetyConfig safetyConfig;

  private DefaultAdminService(Dependencies deps, Config config) {
    this.credentialRepository = deps.credentialRepository();
    this.userLookup = deps.userLookup();
    this.backupCodeService = deps.backupCodeService();
    this.magicLinkService = deps.magicLinkService();
    this.otpService = deps.otpService();
    this.authorizer = config.authorizer();
    this.safetyConfig = config.safetyConfig();
  }

  /**
   * Canonical factory: required collaborators in {@link Dependencies}, tunables in {@link Config}.
   *
   * @since 0.9.1
   */
  public static DefaultAdminService create(Dependencies deps, Config config) {
    Objects.requireNonNull(deps, "deps");
    Objects.requireNonNull(config, "config");
    return new DefaultAdminService(deps, config);
  }

  /**
   * Convenience overload that builds a {@link Config} with the documented defaults (subject-scoped
   * {@link AdminAuthorizer} and default {@link AdminSafetyConfig}).
   *
   * @since 0.9.1
   */
  public static DefaultAdminService create(Dependencies deps) {
    Objects.requireNonNull(deps, "deps");
    return new DefaultAdminService(deps, Config.defaults());
  }

  // -- Account --

  @Override
  public AdminResult<AccountSummary> getAccount(UserHandle actor, UserHandle target) {
    if (!authorize(actor, target)) return new AdminResult.Forbidden<>();
    Optional<UserLookup.UserView> view = userLookup.findViewByHandle(target);
    if (view.isEmpty()) return new AdminResult.NotFound<>();
    int credentialCount = credentialRepository.findByUserHandle(target).size();
    int remaining = remainingBackupCodeCount(target);
    UserLookup.UserView v = view.get();
    return new AdminResult.Success<>(
        new AccountSummary(
            v.handle(),
            v.username(),
            v.displayName(),
            v.emailVerified(),
            v.phoneVerified(),
            credentialCount,
            remaining));
  }

  // -- Credentials --

  @Override
  public AdminResult<List<CredentialSummary>> listCredentials(UserHandle actor, UserHandle target) {
    if (!authorize(actor, target)) return new AdminResult.Forbidden<>();
    List<CredentialSummary> credentials =
        credentialRepository.findByUserHandle(target).stream().map(CredentialSummary::of).toList();
    return new AdminResult.Success<>(credentials);
  }

  @Override
  public AdminResult<List<CredentialSummary>> listCredentialsByAlgorithm(
      UserHandle actor, UserHandle target, int coseAlgorithm) {
    if (!authorize(actor, target)) return new AdminResult.Forbidden<>();
    // Algorithm is read from each credential's already-stored COSE key (no schema change); see
    // CredentialAlgorithms / ADR 0019.
    List<CredentialSummary> matching =
        credentialRepository.findByUserHandle(target).stream()
            .filter(record -> CredentialAlgorithms.usesAlgorithm(record, coseAlgorithm))
            .map(CredentialSummary::of)
            .toList();
    return new AdminResult.Success<>(matching);
  }

  @Override
  public AdminResult<CredentialSummary> renameCredential(
      UserHandle actor, UserHandle target, CredentialId credentialId, String newLabel) {
    if (!authorize(actor, target)) return new AdminResult.Forbidden<>();
    if (newLabel == null || newLabel.isBlank()) {
      return new AdminResult.ValidationFailed<>("label must be non-blank");
    }
    Optional<CredentialRecord> cred = credentialRepository.findByCredentialId(credentialId);
    if (cred.isEmpty() || !cred.get().userHandle().equals(target)) {
      return new AdminResult.NotFound<>();
    }
    credentialRepository.updateLabel(target, credentialId, newLabel);
    CredentialRecord updated = credentialRepository.findByCredentialId(credentialId).orElseThrow();
    return new AdminResult.Success<>(CredentialSummary.of(updated));
  }

  @Override
  public AdminResult<Void> deleteCredential(
      UserHandle actor, UserHandle target, CredentialId credentialId) {
    if (!authorize(actor, target)) return new AdminResult.Forbidden<>();
    Optional<CredentialRecord> cred = credentialRepository.findByCredentialId(credentialId);
    if (cred.isEmpty() || !cred.get().userHandle().equals(target)) {
      return new AdminResult.NotFound<>();
    }
    if (!safetyConfig.allowDeleteWithoutBackupCodes()) {
      List<CredentialRecord> all = credentialRepository.findByUserHandle(target);
      boolean lastOne = all.size() == 1 && all.get(0).credentialId().equals(credentialId);
      // remainingBackupCodeCount() returns 0 when the backup-code feature is not configured, so the
      // anti-lockout guard stays fail-closed: deleting the last credential is still blocked unless
      // the host opts in via AdminSafetyConfig.allowDeleteWithoutBackupCodes().
      if (lastOne && remainingBackupCodeCount(target) == 0) {
        return new AdminResult.Conflict<>(
            "Cannot delete the last credential while no backup codes remain.");
      }
    }
    credentialRepository.delete(target, credentialId);
    // Structured deletion event — replaces the per-implementation audit-table writes the
    // soft-delete path used to emit. Hosts capture this through their normal log pipeline.
    LOG.info(
        "pkauth.credential.deleted credential_id_b64={} user_handle_b64={}",
        Base64Url.encode(credentialId.value()),
        Base64Url.encode(target.value()));
    return new AdminResult.Success<>(null);
  }

  // -- Backup codes --

  @Override
  public AdminResult<BackupCodesGenerated> regenerateBackupCodes(
      UserHandle actor, UserHandle target) {
    if (!authorize(actor, target)) return new AdminResult.Forbidden<>();
    if (backupCodeService == null) return notConfigured("backup codes");
    List<String> plaintext = backupCodeService.regenerateBackupCodes(target);
    return new AdminResult.Success<>(new BackupCodesGenerated(plaintext));
  }

  @Override
  public AdminResult<Integer> remainingBackupCodes(UserHandle actor, UserHandle target) {
    if (!authorize(actor, target)) return new AdminResult.Forbidden<>();
    if (backupCodeService == null) return notConfigured("backup codes");
    return new AdminResult.Success<>(backupCodeService.remainingCount(target));
  }

  // -- Email --

  @Override
  public AdminResult<Void> startEmailVerification(
      UserHandle actor, UserHandle target, String email) {
    if (!authorize(actor, target)) return new AdminResult.Forbidden<>();
    if (email == null || email.isBlank()) {
      return new AdminResult.ValidationFailed<>("email must be non-blank");
    }
    if (magicLinkService == null) return notConfigured("email verification");
    SendResult send = magicLinkService.startEmailVerification(target, email);
    if (send instanceof SendResult.RateLimited) {
      return new AdminResult.RateLimited<>(Duration.ofHours(1));
    }
    // Privacy invariant (item #42): a caller-supplied email that does not match the user's
    // bound address must produce the same 204 as a successful send. Surfacing
    // ValidationFailed here would let a caller probe "is this email bound to this user?".
    // The mismatch is already recorded by MagicLinkService's audit log warning; do NOT
    // re-surface it on the response shape.
    return new AdminResult.Success<>(null);
  }

  @Override
  public AdminResult<UserHandle> finishEmailVerification(String token) {
    if (token == null || token.isBlank()) {
      return new AdminResult.ValidationFailed<>("token must be non-blank");
    }
    if (magicLinkService == null) return notConfigured("email verification");
    ConsumeResult result = magicLinkService.finishVerification(token);
    if (result instanceof ConsumeResult.Success success) {
      // Host apps own the users table; we report success and let the adapter persist the
      // emailVerified flag via UserLookup's host-app-specific update path (out of scope here).
      LOG.info("admin.email.verified user={}", success.userHandle());
      return new AdminResult.Success<>(success.userHandle());
    }
    if (result instanceof ConsumeResult.AlreadyConsumed) {
      return new AdminResult.Conflict<>("token already consumed");
    }
    return new AdminResult.ValidationFailed<>("invalid token");
  }

  // -- Phone --

  @Override
  public AdminResult<OtpDispatchResult> startPhoneVerification(
      UserHandle actor, UserHandle target, String phoneE164) {
    if (!authorize(actor, target)) return new AdminResult.Forbidden<>();
    if (phoneE164 == null || !phoneE164.startsWith("+")) {
      return new AdminResult.ValidationFailed<>("phone must be E.164 format");
    }
    if (otpService == null) return notConfigured("phone verification");
    OtpService.SendResult send = otpService.startVerification(target, phoneE164);
    // Exhaustive switch over the sealed SendResult — a new variant becomes a compile error here
    // rather than a ClassCastException across the AdminResult boundary.
    return switch (send) {
      case OtpService.SendResult.Sent sent ->
          new AdminResult.Success<>(new OtpDispatchResult(sent.otpId()));
      case OtpService.SendResult.RateLimited rateLimited ->
          new AdminResult.RateLimited<>(Duration.ofMinutes(15));
    };
  }

  @Override
  public AdminResult<PhoneVerificationResult> finishPhoneVerification(
      UserHandle actor, UserHandle target, String phoneE164, String code) {
    if (!authorize(actor, target)) return new AdminResult.Forbidden<>();
    if (phoneE164 == null || code == null) {
      return new AdminResult.ValidationFailed<>("phone and code are required");
    }
    if (otpService == null) return notConfigured("phone verification");
    OtpService.VerifyResult result = otpService.finishVerification(target, phoneE164, code);
    return new AdminResult.Success<>(
        switch (result) {
          case OtpService.VerifyResult.Success s -> new PhoneVerificationResult.Verified();
          case OtpService.VerifyResult.NoActiveOtp n -> new PhoneVerificationResult.Expired();
          case OtpService.VerifyResult.Expired e -> new PhoneVerificationResult.Expired();
          case OtpService.VerifyResult.AttemptsExceeded a ->
              new PhoneVerificationResult.AttemptsExceeded();
          case OtpService.VerifyResult.CodeMismatch m ->
              new PhoneVerificationResult.Mismatch(m.remainingAttempts());
        });
  }

  // -- helpers --

  private boolean authorize(UserHandle actor, UserHandle target) {
    Objects.requireNonNull(actor, "actor");
    Objects.requireNonNull(target, "target");
    return authorizer.canAct(actor, target);
  }

  /**
   * Backup-code count for {@code target}, or {@code 0} when the backup-code feature is not
   * configured. Returning 0 (rather than throwing) keeps the {@code deleteCredential} anti-lockout
   * guard fail-closed for passkey-only hosts.
   */
  private int remainingBackupCodeCount(UserHandle target) {
    return backupCodeService == null ? 0 : backupCodeService.remainingCount(target);
  }

  private static <T> AdminResult<T> notConfigured(String feature) {
    return new AdminResult.ValidationFailed<>(feature + " is not configured on this deployment");
  }

  /**
   * Holder of the {@link DefaultAdminService} collaborators. {@code credentialRepository} and
   * {@code userLookup} are always required; the three alt-flow services ({@code backupCodeService},
   * {@code magicLinkService}, {@code otpService}) are <b>optional</b> — pass {@code null} for any
   * feature a passkey-only host does not run. Admin operations for an absent feature return {@link
   * AdminResult.ValidationFailed} ("… is not configured"), and the {@code deleteCredential}
   * anti-lockout guard treats an absent backup-code service as zero remaining codes (fail-closed).
   *
   * <p>Pass an instance to {@link #create(Dependencies)} (or the {@link #create(Dependencies,
   * Config)} overload) to construct a service. Using a record keeps construction sites concise and
   * self-documenting through Java's named component syntax.
   *
   * @since 2.0.0
   */
  public record Dependencies(
      CredentialRepository credentialRepository,
      UserLookup userLookup,
      @Nullable BackupCodeService backupCodeService,
      @Nullable MagicLinkService magicLinkService,
      @Nullable OtpService otpService) {
    /** Compact constructor — enforces non-null on the two always-required collaborators. */
    public Dependencies {
      Objects.requireNonNull(credentialRepository, "credentialRepository");
      Objects.requireNonNull(userLookup, "userLookup");
    }

    /**
     * Convenience for a passkey-only deployment: credentials and user lookup only, with every
     * alt-flow service absent.
     *
     * @since 2.0.0
     */
    public static Dependencies passkeyOnly(
        CredentialRepository credentialRepository, UserLookup userLookup) {
      return new Dependencies(credentialRepository, userLookup, null, null, null);
    }
  }

  /**
   * Tunable configuration for {@link DefaultAdminService}.
   *
   * <p>{@link #defaults()} wires {@link AdminAuthorizer#subjectScoped()} and {@link
   * AdminSafetyConfig#defaults()}.
   *
   * @since 0.9.1
   */
  public record Config(AdminAuthorizer authorizer, AdminSafetyConfig safetyConfig) {
    /** Compact constructor — enforces non-null on every field. */
    public Config {
      Objects.requireNonNull(authorizer, "authorizer");
      Objects.requireNonNull(safetyConfig, "safetyConfig");
    }

    /**
     * Returns a {@link Config} with the documented defaults.
     *
     * @since 0.9.1
     */
    public static Config defaults() {
      return new Config(AdminAuthorizer.subjectScoped(), AdminSafetyConfig.defaults());
    }
  }
}
