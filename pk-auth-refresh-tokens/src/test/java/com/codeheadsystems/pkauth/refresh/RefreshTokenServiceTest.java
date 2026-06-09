// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.refresh.spi.RefreshTokenRepository;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.testkit.InMemoryRefreshTokenRepository;
import com.codeheadsystems.pkauth.testkit.RefreshTokenScenarios;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * Drives the shared {@link RefreshTokenScenarios} (so {@code RefreshTokenService} coverage is
 * attributed to this module and its JaCoCo gate is actually enforced) plus the service-level edge
 * cases the cross-backend parity scenarios don't reach: wire-format parsing, the deprecated default
 * {@code amr} overload, argument validation, revoked-vs-replayed disambiguation, and the
 * deterministic-RNG constructor.
 */
class RefreshTokenServiceTest {

  private static final Instant NOW = Instant.parse("2026-05-16T12:00:00Z");
  private static final UserHandle USER = UserHandle.of(new byte[] {1, 2, 3});
  private static final String AUDIENCE = "web";
  private static final List<String> AMR = List.of("pkauth", "webauthn");

  private final InMemoryRefreshTokenRepository repository = new InMemoryRefreshTokenRepository();
  private final RefreshTokenService service =
      new RefreshTokenService(
          repository, RefreshTokenConfig.defaults(), fixedClock(NOW), new SecureRandom());

  // -- Shared parity scenarios (coverage attribution + behavioural contract) ----------------

  @Test
  void scenario_issueRotateRevokeHappyPath() {
    scenarios().issueRotateRevokeHappyPath();
  }

  @Test
  void scenario_rotationUpdatesFamilyChainAndChildLinksToParent() {
    scenarios().rotationUpdatesFamilyChainAndChildLinksToParent();
  }

  @Test
  void scenario_replayOfUsedTokenScorchesEntireFamily() {
    scenarios().replayOfUsedTokenScorchesEntireFamily();
  }

  @Test
  void scenario_expiredTokenRotationReturnsExpired() {
    scenarios().expiredTokenRotationReturnsExpired();
  }

  @Test
  void scenario_unknownRefreshIdReturnsUnknown() {
    scenarios().unknownRefreshIdReturnsUnknown();
  }

  @Test
  void scenario_wrongSecretReturnsUnknownAndDoesNotBurnLegitToken() {
    scenarios().wrongSecretReturnsUnknownAndDoesNotBurnLegitToken();
  }

  @Test
  void scenario_revokeFamilyIsIdempotent() {
    scenarios().revokeFamilyIsIdempotent();
  }

  @Test
  void scenario_revokeAllForUserRevokesEveryActiveFamily() {
    scenarios().revokeAllForUserRevokesEveryActiveFamily();
  }

  @Test
  void scenario_concurrentRotationExactlyOneSucceedsFamilyRevoked() throws Exception {
    scenarios().concurrentRotationExactlyOneSucceedsFamilyRevoked();
  }

  // -- issue() ------------------------------------------------------------------------------

  @Test
  @SuppressWarnings("deprecation") // intentionally exercises the deprecated default-amr overload
  void deprecatedIssueDefaultsAmrToUser() {
    RefreshTokenPair pair = service.issue(USER, AUDIENCE, Optional.empty());
    assertThat(pair.record().amr()).containsExactly("user");
    // The default amr is carried through a rotation unchanged.
    RotateResult.Success rotated = (RotateResult.Success) service.rotate(pair.wireToken());
    assertThat(rotated.claimsForAccessIssue().amr()).containsExactly("user");
  }

  @Test
  void issueRejectsBlankAudience() {
    assertThatThrownBy(() -> service.issue(USER, "  ", Optional.empty(), AMR))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("audience");
  }

  @Test
  void issueRejectsNullArguments() {
    assertThatThrownBy(() -> service.issue(null, AUDIENCE, Optional.empty(), AMR))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> service.issue(USER, null, Optional.empty(), AMR))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> service.issue(USER, AUDIENCE, null, AMR))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> service.issue(USER, AUDIENCE, Optional.empty(), null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void issueCarriesDeviceIdAndAudienceOntoRecord() {
    RefreshTokenPair pair = service.issue(USER, "cli", Optional.of("device-7"), AMR);
    assertThat(pair.record().audience()).isEqualTo("cli");
    assertThat(pair.record().deviceId()).hasValue("device-7");
    assertThat(pair.record().issuedAt()).isEqualTo(NOW);
    // Default single-TTL policy is 14 days.
    assertThat(pair.record().expiresAt()).isEqualTo(NOW.plus(Duration.ofDays(14)));
  }

  // -- rotate() wire-format parsing ---------------------------------------------------------

  @Test
  void rotateWithNoDotSeparatorIsUnknown() {
    assertThat(service.rotate("noseparator")).isInstanceOf(RotateResult.Unknown.class);
  }

  @Test
  void rotateWithLeadingDotIsUnknown() {
    assertThat(service.rotate(".secretpart")).isInstanceOf(RotateResult.Unknown.class);
  }

  @Test
  void rotateWithTrailingDotIsUnknown() {
    assertThat(service.rotate("refreshId.")).isInstanceOf(RotateResult.Unknown.class);
  }

  @Test
  void rotateWithNonBase64SecretIsUnknown() {
    // '*' is outside the base64url alphabet → decode throws → parse returns null → Unknown.
    assertThat(service.rotate("refreshId.****")).isInstanceOf(RotateResult.Unknown.class);
  }

  @Test
  void rotateWithEmptySecretAfterDecodeIsUnknown() {
    // An empty base64url string decodes to zero bytes → parse rejects → Unknown.
    String emptySecret = Base64Url.encode(new byte[0]);
    assertThat(service.rotate("refreshId." + emptySecret)).isInstanceOf(RotateResult.Unknown.class);
  }

  @Test
  void rotateRejectsNull() {
    assertThatThrownBy(() -> service.rotate(null)).isInstanceOf(NullPointerException.class);
  }

  // -- rotate() against revoked rows --------------------------------------------------------

  @Test
  void rotateOfFamilyRevokedForNonReplayReasonReturnsRevoked() {
    RefreshTokenPair root = service.issue(USER, AUDIENCE, Optional.empty(), AMR);
    service.revokeFamily(root.record().familyId(), RevokeReason.ADMIN);
    assertThat(service.rotate(root.wireToken()))
        .isInstanceOfSatisfying(
            RotateResult.Revoked.class, r -> assertThat(r.reason()).isEqualTo(RevokeReason.ADMIN));
  }

  @Test
  void rotateOfReplayScorchedFamilyReturnsReplayedNotRevoked() {
    RefreshTokenPair root = service.issue(USER, AUDIENCE, Optional.empty(), AMR);
    RotateResult.Success first = (RotateResult.Success) service.rotate(root.wireToken());
    // Re-present the now-used root: scorches the family with ROTATION_REPLAY.
    assertThat(service.rotate(root.wireToken())).isInstanceOf(RotateResult.Replayed.class);
    // The successor's family is ROTATION_REPLAY-revoked → Replayed (consistent outcome), not
    // Revoked.
    assertThat(service.rotate(first.pair().wireToken())).isInstanceOf(RotateResult.Replayed.class);
  }

  // -- revoke / listing ---------------------------------------------------------------------

  @Test
  void revokeAllForUserReturnsAffectedCount() {
    service.issue(USER, AUDIENCE, Optional.empty(), AMR);
    service.issue(USER, "cli", Optional.empty(), AMR);
    assertThat(service.revokeAllForUser(USER, RevokeReason.LOGOUT)).isEqualTo(2);
    // Idempotent: nothing left to revoke the second time.
    assertThat(service.revokeAllForUser(USER, RevokeReason.LOGOUT)).isZero();
  }

  @Test
  void listForUserProjectsSummariesWithoutSecrets() {
    RefreshTokenPair pair = service.issue(USER, AUDIENCE, Optional.of("dev-1"), AMR);
    List<RefreshTokenSummary> summaries = service.listForUser(USER);
    assertThat(summaries).hasSize(1);
    RefreshTokenSummary s = summaries.get(0);
    assertThat(s.refreshId()).isEqualTo(pair.record().refreshId());
    assertThat(s.familyId()).isEqualTo(pair.record().familyId());
    assertThat(s.audience()).isEqualTo(AUDIENCE);
    assertThat(s.deviceId()).hasValue("dev-1");
    assertThat(s.revokedAt()).isEmpty();
  }

  @Test
  void listForUserIsEmptyForUnknownUser() {
    assertThat(service.listForUser(UserHandle.of(new byte[] {9, 9}))).isEmpty();
  }

  @Test
  void revokeAndListNullChecks() {
    assertThatThrownBy(() -> service.revokeFamily(null, RevokeReason.ADMIN))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> service.revokeFamily("fam", null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> service.revokeAllForUser(null, RevokeReason.ADMIN))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> service.revokeAllForUser(USER, null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> service.listForUser(null)).isInstanceOf(NullPointerException.class);
  }

  // -- constructors -------------------------------------------------------------------------

  @Test
  void deterministicRngConstructorProducesStableWireToken() {
    RefreshTokenRepository repoA = new InMemoryRefreshTokenRepository();
    RefreshTokenRepository repoB = new InMemoryRefreshTokenRepository();
    RefreshTokenService a =
        new RefreshTokenService(
            repoA, RefreshTokenConfig.defaults(), fixedClock(NOW), seededRandom());
    RefreshTokenService b =
        new RefreshTokenService(
            repoB, RefreshTokenConfig.defaults(), fixedClock(NOW), seededRandom());
    assertThat(a.issue(USER, AUDIENCE, Optional.empty(), AMR).wireToken())
        .isEqualTo(b.issue(USER, AUDIENCE, Optional.empty(), AMR).wireToken());
  }

  @Test
  void constructorRejectsNullDependencies() {
    RefreshTokenConfig config = RefreshTokenConfig.defaults();
    ClockProvider clock = fixedClock(NOW);
    assertThatThrownBy(() -> new RefreshTokenService(null, config, clock))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new RefreshTokenService(repository, null, clock))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new RefreshTokenService(repository, config, null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(
            () -> new RefreshTokenService(repository, config, clock, (SecureRandom) null))
        .isInstanceOf(NullPointerException.class);
  }

  // -- helpers ------------------------------------------------------------------------------

  private RefreshTokenScenarios scenarios() {
    return new RefreshTokenScenarios(new InMemoryRefreshTokenRepository());
  }

  private static SecureRandom seededRandom() {
    // SHA1PRNG with a fixed seed is reproducible across instances — fine for a test asserting
    // determinism (never for production token generation).
    try {
      SecureRandom r = SecureRandom.getInstance("SHA1PRNG");
      r.setSeed(42L);
      return r;
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static ClockProvider fixedClock(Instant instant) {
    return ClockProvider.fromClock(Clock.fixed(instant, ZoneOffset.UTC));
  }
}
