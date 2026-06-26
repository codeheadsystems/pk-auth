// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * The pk-auth-specific claim set embedded in every issued JWT. Maps to the JWT body fields
 * described in brief §6.2.
 *
 * @param userHandle the {@code sub} subject (base64url-encoded on the wire)
 * @param method which factor proved possession of this user's account
 * @param credentialId WebAuthn credential id; required iff {@link AuthMethod#PASSKEY}, else null
 * @param amr RFC 8176-compatible authentication-method-reference values
 * @param additionalClaims optional extra claims merged into the JWT body
 * @param audience the audience this token is for; when {@code null} the issuer uses {@link
 *     JwtConfig#defaultAudience()}. Drives per-audience TTL lookup via {@link TokenTtlPolicy}.
 */
public record JwtClaims(
    UserHandle userHandle,
    AuthMethod method,
    byte @Nullable [] credentialId,
    List<String> amr,
    @Nullable Map<String, Object> additionalClaims,
    @Nullable String audience) {

  /**
   * Claim names the issuer sets itself and that {@link #additionalClaims} must never carry. Because
   * the issuer merges {@code additionalClaims} into the same JWT body after writing these, allowing
   * a caller to supply one would let it silently overwrite a security-critical value (e.g. a future
   * {@code exp}, an impersonating {@code sub}, or a forged {@code aud}/{@code iss}). The RFC 7519
   * registered set plus the {@code pkauth.*} private claims mirror {@code
   * PkAuthJwtValidator.removeKnownClaims}.
   *
   * @since 2.1.0
   */
  private static final Set<String> RESERVED_CLAIM_NAMES =
      Set.of(
          "iss",
          "sub",
          "aud",
          "iat",
          "nbf",
          "exp",
          "jti",
          "pkauth.method",
          "pkauth.cred",
          "pkauth.amr");

  public JwtClaims {
    Objects.requireNonNull(userHandle, "userHandle");
    Objects.requireNonNull(method, "method");
    Objects.requireNonNull(amr, "amr");
    if (additionalClaims != null) {
      for (String key : additionalClaims.keySet()) {
        if (RESERVED_CLAIM_NAMES.contains(key)) {
          throw new IllegalArgumentException(
              "additionalClaims must not contain the reserved claim '" + key + "'");
        }
      }
    }
    if (method == AuthMethod.PASSKEY && credentialId == null) {
      throw new IllegalArgumentException("credentialId is required when method == PASSKEY");
    }
    if (method != AuthMethod.PASSKEY && credentialId != null) {
      throw new IllegalArgumentException("credentialId must be null when method != PASSKEY");
    }
    if (audience != null && audience.isBlank()) {
      throw new IllegalArgumentException("audience must be non-blank when present");
    }
    if (credentialId != null) {
      credentialId = credentialId.clone();
    }
    amr = List.copyOf(amr);
    if (additionalClaims != null) {
      additionalClaims = Map.copyOf(additionalClaims);
    }
  }

  /**
   * Five-arg constructor preserved for callers that pre-date the per-audience TTL work; audience
   * defaults to {@code null} (issuer uses {@link JwtConfig#defaultAudience()}).
   */
  public JwtClaims(
      UserHandle userHandle,
      AuthMethod method,
      byte @Nullable [] credentialId,
      List<String> amr,
      @Nullable Map<String, Object> additionalClaims) {
    this(userHandle, method, credentialId, amr, additionalClaims, null);
  }

  /** Convenience factory for passkey-issued tokens (uses {@code defaultAudience} at issue time). */
  public static JwtClaims forPasskey(UserHandle userHandle, byte[] credentialId, List<String> amr) {
    return new JwtClaims(userHandle, AuthMethod.PASSKEY, credentialId, amr, null, null);
  }

  /** Convenience factory for passkey-issued tokens scoped to a specific audience. */
  public static JwtClaims forPasskey(
      UserHandle userHandle, byte[] credentialId, String audience, List<String> amr) {
    return new JwtClaims(userHandle, AuthMethod.PASSKEY, credentialId, amr, null, audience);
  }

  /** Convenience factory for backup-code-issued tokens (uses {@code defaultAudience}). */
  public static JwtClaims forBackupCode(UserHandle userHandle, List<String> amr) {
    return new JwtClaims(userHandle, AuthMethod.BACKUP_CODE, null, amr, null, null);
  }

  /** Convenience factory for backup-code-issued tokens scoped to a specific audience. */
  public static JwtClaims forBackupCode(UserHandle userHandle, String audience, List<String> amr) {
    return new JwtClaims(userHandle, AuthMethod.BACKUP_CODE, null, amr, null, audience);
  }

  /** Convenience factory for magic-link-issued tokens (uses {@code defaultAudience}). */
  public static JwtClaims forMagicLink(UserHandle userHandle, List<String> amr) {
    return new JwtClaims(userHandle, AuthMethod.MAGIC_LINK, null, amr, null, null);
  }

  /** Convenience factory for magic-link-issued tokens scoped to a specific audience. */
  public static JwtClaims forMagicLink(UserHandle userHandle, String audience, List<String> amr) {
    return new JwtClaims(userHandle, AuthMethod.MAGIC_LINK, null, amr, null, audience);
  }

  /**
   * Convenience factory for refresh-derived access tokens (minted as the access leg of a refresh
   * rotation). Always carries {@link AuthMethod#REFRESH}.
   *
   * @since 1.1.0
   */
  public static JwtClaims forRefresh(UserHandle userHandle, String audience, List<String> amr) {
    return new JwtClaims(userHandle, AuthMethod.REFRESH, null, amr, null, audience);
  }

  @Override
  public byte @Nullable [] credentialId() {
    return credentialId == null ? null : credentialId.clone();
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof JwtClaims other
        && userHandle.equals(other.userHandle)
        && method == other.method
        && Arrays.equals(credentialId, other.credentialId)
        && amr.equals(other.amr)
        && Objects.equals(additionalClaims, other.additionalClaims)
        && Objects.equals(audience, other.audience);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        userHandle, method, Arrays.hashCode(credentialId), amr, additionalClaims, audience);
  }

  @Override
  public String toString() {
    return "JwtClaims[userHandle="
        + userHandle
        + ", method="
        + method
        + ", credentialId="
        + (credentialId == null ? "null" : HexFormat.of().formatHex(credentialId))
        + ", amr="
        + amr
        + ", audience="
        + audience
        + "]";
  }
}
