// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import com.codeheadsystems.pkauth.config.CoseAlgorithm;
import io.micronaut.context.annotation.ConfigurationProperties;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Micronaut configuration bound under the {@code pkauth} prefix. Mirrors the Spring and Dropwizard
 * adapters' shape so the host's {@code application.yml} reads the same. Secrets configurable via
 * env-var with the standard Micronaut mapping: {@code pkauth.jwt.secret} ↔ {@code
 * PKAUTH_JWT_SECRET}.
 *
 * <p>Relying-party id/name/origins and JWT issuer/audience/secret are required — there are no
 * adapter defaults. Misconfiguration surfaces as a startup failure rather than a silent dev-mode
 * boot.
 */
@ConfigurationProperties("pkauth")
public final class PkAuthConfiguration {

  private RelyingParty relyingParty = new RelyingParty();
  private Jwt jwt = new Jwt();
  private Ceremony ceremony = new Ceremony();
  private Otp otp = new Otp();
  private boolean devMode;

  private Refresh refresh = new Refresh();

  public RelyingParty getRelyingParty() {
    return relyingParty;
  }

  public void setRelyingParty(RelyingParty v) {
    this.relyingParty = v;
  }

  public Jwt getJwt() {
    return jwt;
  }

  public void setJwt(Jwt v) {
    this.jwt = v;
  }

  public Ceremony getCeremony() {
    return ceremony;
  }

  public void setCeremony(Ceremony v) {
    this.ceremony = v;
  }

  public Otp getOtp() {
    return otp;
  }

  public void setOtp(Otp v) {
    this.otp = v;
  }

  /**
   * Refresh-token tunables. Only consulted when a {@code RefreshTokenRepository} bean is bound in
   * the host context.
   *
   * @since 1.1.0
   */
  public Refresh getRefresh() {
    return refresh;
  }

  public void setRefresh(Refresh refresh) {
    this.refresh = refresh;
  }

  /**
   * Whether to enable in-memory testkit SPIs and dev-only logging senders, plus per-startup random
   * OTP pepper auto-generation when {@code pkauth.otp.pepper} is unset. Defaults to {@code false} —
   * production deployments must supply real SPI beans / senders / pepper.
   *
   * @return {@code true} when {@code pkauth.dev-mode=true}, {@code false} otherwise
   * @since 0.9.1
   */
  public boolean isDevMode() {
    return devMode;
  }

  /**
   * Bind the {@code pkauth.dev-mode} property.
   *
   * @param devMode whether dev-mode wiring is enabled
   * @since 0.9.1
   */
  public void setDevMode(boolean devMode) {
    this.devMode = devMode;
  }

  /**
   * Ceremony tunables forwarded to {@code CeremonyConfig}. Same default and key as the Spring
   * adapter's {@code pkauth.ceremony.challengeTtl}.
   */
  @ConfigurationProperties("ceremony")
  public static final class Ceremony {
    private Duration challengeTtl = Duration.ofMinutes(5);
    @Nullable private List<CoseAlgorithm> offeredAlgorithms;
    @Nullable private List<CoseAlgorithm> acceptedAlgorithms;

    public Duration getChallengeTtl() {
      return challengeTtl;
    }

    public void setChallengeTtl(Duration challengeTtl) {
      this.challengeTtl = challengeTtl;
    }

    /** COSE algorithms advertised in create-options; null = core default (ES256, EdDSA, RS256). */
    @Nullable
    public List<CoseAlgorithm> getOfferedAlgorithms() {
      return offeredAlgorithms;
    }

    public void setOfferedAlgorithms(@Nullable List<CoseAlgorithm> offeredAlgorithms) {
      this.offeredAlgorithms = offeredAlgorithms;
    }

    /** COSE algorithms accepted on verify; null = core default union (adds ES384, RS384). */
    @Nullable
    public List<CoseAlgorithm> getAcceptedAlgorithms() {
      return acceptedAlgorithms;
    }

    public void setAcceptedAlgorithms(@Nullable List<CoseAlgorithm> acceptedAlgorithms) {
      this.acceptedAlgorithms = acceptedAlgorithms;
    }
  }

  /**
   * Relying-party identity nested config. {@code id}, {@code name}, and {@code origins} are all
   * required — there are no defaults. {@link PkAuthFactory} validates them at startup.
   */
  @ConfigurationProperties("relying-party")
  public static final class RelyingParty {
    private @Nullable String id;
    private @Nullable String name;
    private @Nullable List<String> origins;

    public @Nullable String getId() {
      return id;
    }

    public void setId(@Nullable String id) {
      this.id = id;
    }

    public @Nullable String getName() {
      return name;
    }

    public void setName(@Nullable String name) {
      this.name = name;
    }

    public @Nullable List<String> getOrigins() {
      return origins;
    }

    public void setOrigins(@Nullable List<String> origins) {
      this.origins = origins;
    }
  }

  /**
   * JWT issuance and validation config. {@code issuer}, {@code audience}, and {@code secret} are
   * all required — there are no adapter defaults. {@link PkAuthFactory} validates them at startup.
   *
   * <p>{@code defaultTtl} sets the access-token TTL applied to audiences not listed in {@code
   * ttlsByAudience}; null defers to {@link
   * com.codeheadsystems.pkauth.jwt.JwtConfig#DEFAULT_TOKEN_TTL}. Keys present in {@code
   * ttlsByAudience} are recognised by the validator via {@link
   * com.codeheadsystems.pkauth.jwt.TokenTtlPolicy#knownAudiences()}.
   */
  @ConfigurationProperties("jwt")
  public static final class Jwt {
    private @Nullable String issuer;
    private @Nullable String audience;
    private @Nullable String secret;
    private @Nullable Duration defaultTtl;
    private @Nullable Map<String, Duration> ttlsByAudience;

    public @Nullable String getIssuer() {
      return issuer;
    }

    public void setIssuer(@Nullable String issuer) {
      this.issuer = issuer;
    }

    public @Nullable String getAudience() {
      return audience;
    }

    public void setAudience(@Nullable String audience) {
      this.audience = audience;
    }

    public @Nullable String getSecret() {
      return secret;
    }

    public void setSecret(@Nullable String secret) {
      this.secret = secret;
    }

    public @Nullable Duration getDefaultTtl() {
      return defaultTtl;
    }

    public void setDefaultTtl(@Nullable Duration defaultTtl) {
      this.defaultTtl = defaultTtl;
    }

    public @Nullable Map<String, Duration> getTtlsByAudience() {
      return ttlsByAudience;
    }

    public void setTtlsByAudience(@Nullable Map<String, Duration> ttlsByAudience) {
      this.ttlsByAudience = ttlsByAudience;
    }
  }

  /**
   * OTP service tunables.
   *
   * <p>{@code pkauth.otp.pepper} is a Base64-encoded server-side HMAC pepper (≥ 16 decoded bytes;
   * 32+ recommended). Required in production. When unset, the factory will only auto-generate a
   * per-startup random pepper if {@code pkauth.dev-mode=true}. A per-startup pepper invalidates
   * outstanding OTPs across restarts and across cluster instances.
   */
  @ConfigurationProperties("otp")
  public static final class Otp {
    private @Nullable String pepper;

    public @Nullable String getPepper() {
      return pepper;
    }

    public void setPepper(@Nullable String pepper) {
      this.pepper = pepper;
    }
  }

  /**
   * Refresh-token block. {@code defaultTtl} and {@code ttlsByAudience} feed the {@link
   * com.codeheadsystems.pkauth.refresh.RefreshTtlPolicy}; {@code cleanupRetention} sets the
   * forensic retention window. Null fields fall through to {@link
   * com.codeheadsystems.pkauth.refresh.RefreshTokenConfig#defaults()}.
   *
   * @since 1.1.0
   */
  @ConfigurationProperties("refresh")
  public static final class Refresh {
    private @Nullable Duration defaultTtl;
    private @Nullable Map<String, Duration> ttlsByAudience;
    private @Nullable Duration cleanupRetention;

    public @Nullable Duration getDefaultTtl() {
      return defaultTtl;
    }

    public void setDefaultTtl(@Nullable Duration defaultTtl) {
      this.defaultTtl = defaultTtl;
    }

    public @Nullable Map<String, Duration> getTtlsByAudience() {
      return ttlsByAudience;
    }

    public void setTtlsByAudience(@Nullable Map<String, Duration> ttlsByAudience) {
      this.ttlsByAudience = ttlsByAudience;
    }

    public @Nullable Duration getCleanupRetention() {
      return cleanupRetention;
    }

    public void setCleanupRetention(@Nullable Duration cleanupRetention) {
      this.cleanupRetention = cleanupRetention;
    }
  }
}
