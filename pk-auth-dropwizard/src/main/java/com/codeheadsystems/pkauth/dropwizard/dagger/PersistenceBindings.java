// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.dagger;

import com.codeheadsystems.pkauth.jwt.AccessTokenStore;
import com.codeheadsystems.pkauth.refresh.spi.RefreshTokenRepository;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * SPI bag the host application hands to the bundle so the same Dagger graph supports JDBI,
 * DynamoDB, and in-memory persistence without re-generating components per backend. Brief §6.11 —
 * "@Module PersistenceModule (overridable)".
 *
 * <p>Only the credential, user-lookup, and challenge-store SPIs are required (they back the four
 * ceremony endpoints). Backup-code, magic-link, and OTP SPIs are optional — supply them when
 * registering the admin resource.
 */
public final class PersistenceBindings {

  private final CredentialRepository credentialRepository;
  private final UserLookup userLookup;
  private final ChallengeStore challengeStore;
  @Nullable private final BackupCodeRepository backupCodeRepository;
  @Nullable private final OtpRepository otpRepository;
  private final AccessTokenStore accessTokenStore;
  @Nullable private final RefreshTokenRepository refreshTokenRepository;

  private PersistenceBindings(Builder b) {
    this.credentialRepository =
        Objects.requireNonNull(b.credentialRepository, "credentialRepository");
    this.userLookup = Objects.requireNonNull(b.userLookup, "userLookup");
    this.challengeStore = Objects.requireNonNull(b.challengeStore, "challengeStore");
    this.backupCodeRepository = b.backupCodeRepository;
    this.otpRepository = b.otpRepository;
    this.accessTokenStore =
        b.accessTokenStore == null ? AccessTokenStore.noop() : b.accessTokenStore;
    this.refreshTokenRepository = b.refreshTokenRepository;
  }

  public static Builder builder() {
    return new Builder();
  }

  public CredentialRepository credentialRepository() {
    return credentialRepository;
  }

  public UserLookup userLookup() {
    return userLookup;
  }

  public ChallengeStore challengeStore() {
    return challengeStore;
  }

  @Nullable
  public BackupCodeRepository backupCodeRepository() {
    return backupCodeRepository;
  }

  @Nullable
  public OtpRepository otpRepository() {
    return otpRepository;
  }

  /**
   * Returns the configured {@link AccessTokenStore}. Defaults to {@link AccessTokenStore#noop()} —
   * stateless JWT behaviour. Hosts that want server-side access-token revocation supply a real
   * store (e.g. {@code JdbiAccessTokenStore}) via {@link
   * Builder#accessTokenStore(AccessTokenStore)}.
   *
   * @since 1.1.0
   */
  public AccessTokenStore accessTokenStore() {
    return accessTokenStore;
  }

  /**
   * Returns the configured {@link RefreshTokenRepository}, or {@code null} when the host hasn't
   * wired refresh tokens. The bundle mounts {@code /auth/refresh} only when this is non-null, with
   * or without alt-flow auto-wiring.
   *
   * @since 1.1.0
   */
  @Nullable
  public RefreshTokenRepository refreshTokenRepository() {
    return refreshTokenRepository;
  }

  /** Builder. */
  public static final class Builder {
    @Nullable private CredentialRepository credentialRepository;
    @Nullable private UserLookup userLookup;
    @Nullable private ChallengeStore challengeStore;
    @Nullable private BackupCodeRepository backupCodeRepository;
    @Nullable private OtpRepository otpRepository;
    @Nullable private AccessTokenStore accessTokenStore;
    @Nullable private RefreshTokenRepository refreshTokenRepository;

    private Builder() {}

    public Builder credentialRepository(CredentialRepository v) {
      this.credentialRepository = v;
      return this;
    }

    public Builder userLookup(UserLookup v) {
      this.userLookup = v;
      return this;
    }

    public Builder challengeStore(ChallengeStore v) {
      this.challengeStore = v;
      return this;
    }

    public Builder backupCodeRepository(BackupCodeRepository v) {
      this.backupCodeRepository = v;
      return this;
    }

    public Builder otpRepository(OtpRepository v) {
      this.otpRepository = v;
      return this;
    }

    /**
     * Supplies a real {@link AccessTokenStore} for stateful access-token mode. Omit (or pass null)
     * to keep stateless JWT behaviour via {@link AccessTokenStore#noop()}.
     *
     * @since 1.1.0
     */
    public Builder accessTokenStore(@Nullable AccessTokenStore v) {
      this.accessTokenStore = v;
      return this;
    }

    /**
     * Supplies a {@link RefreshTokenRepository} so the bundle mounts {@code /auth/refresh}. Omit to
     * skip refresh-token endpoint registration.
     *
     * @since 1.1.0
     */
    public Builder refreshTokenRepository(RefreshTokenRepository v) {
      this.refreshTokenRepository = v;
      return this;
    }

    public PersistenceBindings build() {
      return new PersistenceBindings(this);
    }
  }
}
