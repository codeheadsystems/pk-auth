// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.refresh.spi.RefreshTokenRepository;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Issues, rotates, and revokes refresh tokens. See ADR 0013 for the family-based replay-defence
 * design and the operational invariants this implementation must preserve.
 *
 * <p>Wire format is {@code "{refreshId}.{secret}"} where both halves are base64url. Only the
 * SHA-256 hash of the raw secret bytes is persisted; the wire token never gets logged.
 *
 * <p>This service does not issue access tokens itself; {@link #rotate(String)} returns the data the
 * caller needs to mint a fresh JWT via {@link com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer}. The
 * two primitives stay composable.
 *
 * @since 1.1.0
 */
public final class RefreshTokenService {

  private static final Logger LOG = LoggerFactory.getLogger(RefreshTokenService.class);

  /** Default {@code amr} applied when a caller issues a refresh token without specifying one. */
  private static final List<String> DEFAULT_AMR = List.of("user");

  private final RefreshTokenRepository repository;
  private final RefreshTokenConfig config;
  private final ClockProvider clockProvider;
  private final SecureRandom random;

  public RefreshTokenService(
      RefreshTokenRepository repository,
      RefreshTokenConfig config,
      ClockProvider clockProvider,
      SecureRandom random) {
    this.repository = Objects.requireNonNull(repository, "repository");
    this.config = Objects.requireNonNull(config, "config");
    this.clockProvider = Objects.requireNonNull(clockProvider, "clockProvider");
    this.random = Objects.requireNonNull(random, "random");
  }

  /**
   * Convenience constructor using a fresh {@link SecureRandom}. Production deployments typically
   * use this; the explicit-RNG ctor exists for tests with deterministic seeds.
   */
  public RefreshTokenService(
      RefreshTokenRepository repository, RefreshTokenConfig config, ClockProvider clockProvider) {
    this(repository, config, clockProvider, new SecureRandom());
  }

  /**
   * Issues a fresh refresh token belonging to a new family (root of the rotation chain), defaulting
   * the carried {@code amr} to {@code ["user"]}.
   *
   * @deprecated since 1.3.0; prefer {@link #issue(UserHandle, String, Optional, List)} so the
   *     refresh family records the original authentication method references (RFC 8176) and
   *     refreshed access tokens reflect how the session was first established instead of a generic
   *     {@code ["user"]}. Retained for source compatibility.
   */
  @Deprecated
  public RefreshTokenPair issue(UserHandle userHandle, String audience, Optional<String> deviceId) {
    return issue(userHandle, audience, deviceId, DEFAULT_AMR);
  }

  /**
   * Issues a fresh refresh token belonging to a new family (root of the rotation chain). Returns
   * the wire token plus the persisted record summary. The supplied {@code amr} (RFC 8176
   * authentication method references describing how the user just authenticated) is stored on the
   * family and carried verbatim into every access token minted from a rotation of this token.
   *
   * @since 1.3.0
   */
  public RefreshTokenPair issue(
      UserHandle userHandle, String audience, Optional<String> deviceId, List<String> amr) {
    Objects.requireNonNull(userHandle, "userHandle");
    Objects.requireNonNull(audience, "audience");
    Objects.requireNonNull(deviceId, "deviceId");
    Objects.requireNonNull(amr, "amr");
    if (audience.isBlank()) {
      throw new IllegalArgumentException("audience must be non-blank");
    }
    Instant now = clockProvider.now();
    String refreshId = randomBase64Url(config.refreshIdBytes());
    byte[] secret = randomBytes(config.secretBytes());
    RefreshTokenRecord record =
        new RefreshTokenRecord(
            refreshId,
            sha256(secret),
            userHandle,
            audience,
            deviceId,
            refreshId, // family root: familyId = refreshId
            Optional.empty(),
            now,
            now.plus(config.ttlPolicy().refreshTtl(audience)),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            amr);
    repository.create(record);
    return new RefreshTokenPair(wireFormat(refreshId, secret), record);
  }

  /**
   * Validates the presented wire token and, if fresh, rotates it: atomically marks the parent used
   * and inserts a successor in the same family. On detection of a replay (a used or revoked token
   * from a known family being presented again) the entire family is scorched and {@link
   * RotateResult.Replayed} is returned.
   */
  public RotateResult rotate(String presentedWireToken) {
    Objects.requireNonNull(presentedWireToken, "presentedWireToken");
    Parsed parsed = parse(presentedWireToken);
    if (parsed == null) {
      return new RotateResult.Unknown();
    }

    Optional<RefreshTokenRecord> maybe = repository.findByRefreshId(parsed.refreshId);
    if (maybe.isEmpty()) {
      return new RotateResult.Unknown();
    }
    RefreshTokenRecord parent = maybe.get();

    // Hash-check the presented secret BEFORE marking used. A wrong secret must never burn a
    // legitimate token. This is an explicit operational invariant; see ADR 0013.
    byte[] presentedHash = sha256(parsed.secret);
    if (!MessageDigest.isEqual(presentedHash, parent.tokenHash())) {
      return new RotateResult.Unknown();
    }

    // Already revoked? A row whose family was scorched in a prior replay carries
    // reason=ROTATION_REPLAY — return Replayed so race losers and replay-after-the-fact callers
    // see a consistent outcome. Other revoke reasons (LOGOUT, USER_DELETED, ADMIN, ...) surface
    // as Revoked so the caller can distinguish "this session was deliberately ended" from "a
    // replay just got detected on this family."
    if (parent.revokedAt().isPresent()) {
      RevokeReason reason = parent.revokedReason().orElse(RevokeReason.ADMIN);
      if (reason == RevokeReason.ROTATION_REPLAY) {
        return new RotateResult.Replayed(parent.familyId(), parent.userHandle());
      }
      return new RotateResult.Revoked(reason);
    }

    Instant now = clockProvider.now();
    if (!parent.expiresAt().isAfter(now)) {
      return new RotateResult.Expired();
    }

    // If the parent is already used (but not yet revoked), this is a replay. Don't even call
    // rotateAtomically — go straight to family scorch. Saves a no-op write and gives a cleaner
    // log signal.
    if (parent.usedAt().isPresent()) {
      scorchFamily(parent);
      return new RotateResult.Replayed(parent.familyId(), parent.userHandle());
    }

    // Fresh enough to attempt rotation. Mint the successor and have the SPI commit both
    // "mark parent used" and "insert successor" atomically (see SPI javadoc).
    String successorId = randomBase64Url(config.refreshIdBytes());
    byte[] successorSecret = randomBytes(config.secretBytes());
    RefreshTokenRecord successor =
        new RefreshTokenRecord(
            successorId,
            sha256(successorSecret),
            parent.userHandle(),
            parent.audience(),
            parent.deviceId(),
            parent.familyId(),
            Optional.of(parent.refreshId()),
            now,
            now.plus(config.ttlPolicy().refreshTtl(parent.audience())),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            parent.amr()); // carry the original authentication method references verbatim

    boolean rotated = repository.rotateAtomically(parent.refreshId(), now, successor);
    if (!rotated) {
      // Lost the race against a concurrent rotator (or the parent flipped to used/revoked after
      // our read). Scorch the family — at most one rotator wins, the rest see Replayed. The
      // scorch is outside the failed rotation so it always commits.
      scorchFamily(parent);
      return new RotateResult.Replayed(parent.familyId(), parent.userHandle());
    }

    String wire = wireFormat(successorId, successorSecret);
    RefreshTokenPair pair = new RefreshTokenPair(wire, successor);
    RotatedClaims claims =
        new RotatedClaims(
            successor.userHandle(), successor.audience(), successor.deviceId(), successor.amr());
    return new RotateResult.Success(pair, claims);
  }

  /** Revokes every unrevoked row in the supplied family. Idempotent. */
  public void revokeFamily(String familyId, RevokeReason reason) {
    Objects.requireNonNull(familyId, "familyId");
    Objects.requireNonNull(reason, "reason");
    int n = repository.revokeFamily(familyId, clockProvider.now(), reason);
    LOG.info("pkauth.refresh.family.revoked family={} reason={} affected={}", familyId, reason, n);
  }

  /**
   * Revokes every unrevoked refresh row for the supplied user. Drives the user-deletion fan-out's
   * refresh-token branch and is also surfaced as an admin "log out everywhere" hook.
   */
  public int revokeAllForUser(UserHandle userHandle, RevokeReason reason) {
    Objects.requireNonNull(userHandle, "userHandle");
    Objects.requireNonNull(reason, "reason");
    int n = repository.revokeAllForUser(userHandle, clockProvider.now(), reason);
    LOG.info(
        "pkauth.refresh.user.revoked user_handle_b64={} reason={} affected={}",
        Base64Url.encode(userHandle.value()),
        reason,
        n);
    return n;
  }

  /** Listing projection for admin / UI surfaces. */
  public List<RefreshTokenSummary> listForUser(UserHandle userHandle) {
    Objects.requireNonNull(userHandle, "userHandle");
    return repository.findByUserHandle(userHandle).stream().map(RefreshTokenSummary::from).toList();
  }

  // -- Internals --------------------------------------------------------------------------

  private void scorchFamily(RefreshTokenRecord triggering) {
    Instant now = clockProvider.now();
    int n = repository.revokeFamily(triggering.familyId(), now, RevokeReason.ROTATION_REPLAY);
    LOG.warn(
        "pkauth.refresh.replay family={} user_handle_b64={} affected={}",
        triggering.familyId(),
        Base64Url.encode(triggering.userHandle().value()),
        n);
  }

  private byte[] randomBytes(int n) {
    byte[] out = new byte[n];
    random.nextBytes(out);
    return out;
  }

  private String randomBase64Url(int byteLen) {
    return Base64Url.encode(randomBytes(byteLen));
  }

  private static String wireFormat(String refreshId, byte[] secret) {
    return refreshId + "." + Base64Url.encode(secret);
  }

  private static byte[] sha256(byte[] in) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(in);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  private static Parsed parse(String wireToken) {
    int dot = wireToken.indexOf('.');
    if (dot <= 0 || dot >= wireToken.length() - 1) {
      return null;
    }
    String refreshId = wireToken.substring(0, dot);
    String secretB64 = wireToken.substring(dot + 1);
    byte[] secret;
    try {
      secret = Base64Url.decode(secretB64);
    } catch (RuntimeException e) {
      return null;
    }
    if (secret.length == 0) {
      return null;
    }
    return new Parsed(refreshId, secret);
  }

  private record Parsed(String refreshId, byte[] secret) {}
}
