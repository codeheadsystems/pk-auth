// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.refresh.RefreshTokenConfig;
import com.codeheadsystems.pkauth.refresh.RefreshTokenPair;
import com.codeheadsystems.pkauth.refresh.RefreshTokenService;
import com.codeheadsystems.pkauth.refresh.RefreshTtlPolicy;
import com.codeheadsystems.pkauth.refresh.RevokeReason;
import com.codeheadsystems.pkauth.refresh.RotateResult;
import com.codeheadsystems.pkauth.refresh.spi.RefreshTokenRepository;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Shared parity scenarios for {@link RefreshTokenRepository} implementations. Drive every method
 * from in-memory, JDBI, and DynamoDB test classes so all three backends honour the same contract —
 * especially the load-bearing {@link #concurrentRotationExactlyOneSucceedsFamilyRevoked()} race
 * test, which is the non-negotiable acceptance criterion from the plan.
 *
 * <p>Construct with a fresh empty repository and a controllable clock. Each scenario is
 * self-contained and can run in isolation.
 *
 * @since 1.1.0
 */
public final class RefreshTokenScenarios {

  private static final Instant NOW = Instant.parse("2026-05-16T12:00:00Z");
  private static final UserHandle USER = UserHandle.of(new byte[] {1, 2, 3});
  private static final String AUDIENCE = "web";
  private static final List<String> AMR = List.of("pkauth", "webauthn");

  private final RefreshTokenRepository repository;
  private final RefreshTokenService service;

  public RefreshTokenScenarios(RefreshTokenRepository repository) {
    this(repository, fixedClock(NOW));
  }

  public RefreshTokenScenarios(RefreshTokenRepository repository, ClockProvider clockProvider) {
    this.repository = Objects.requireNonNull(repository, "repository");
    this.service =
        new RefreshTokenService(
            repository,
            new RefreshTokenConfig(
                RefreshTtlPolicy.fixed(
                    Duration.ofDays(14),
                    Map.of("web", Duration.ofDays(14), "cli", Duration.ofDays(90))),
                32,
                16,
                Duration.ofDays(30)),
            Objects.requireNonNull(clockProvider, "clockProvider"));
  }

  /** Issue → rotate → revoke happy path. */
  public void issueRotateRevokeHappyPath() {
    RefreshTokenPair root = service.issue(USER, AUDIENCE, Optional.empty(), AMR);
    assertThat(root.wireToken()).contains(".");
    assertThat(root.record().userHandle()).isEqualTo(USER);
    assertThat(root.record().familyId()).isEqualTo(root.record().refreshId());

    RotateResult result = service.rotate(root.wireToken());
    assertThat(result).isInstanceOf(RotateResult.Success.class);
    RotateResult.Success success = (RotateResult.Success) result;
    assertThat(success.pair().record().familyId()).isEqualTo(root.record().familyId());
    assertThat(success.pair().record().parentRefreshId()).hasValue(root.record().refreshId());
    assertThat(success.claimsForAccessIssue().userHandle()).isEqualTo(USER);
    assertThat(success.claimsForAccessIssue().audience()).isEqualTo(AUDIENCE);
    // amr is persisted on the family and carried verbatim through rotation (survives the backend
    // round-trip), so a refreshed access token reflects the original authentication method.
    assertThat(root.record().amr()).isEqualTo(AMR);
    assertThat(success.pair().record().amr()).isEqualTo(AMR);
    assertThat(success.claimsForAccessIssue().amr()).isEqualTo(AMR);

    // Revoke the family — subsequent rotates of the successor return Revoked.
    service.revokeFamily(root.record().familyId(), RevokeReason.LOGOUT);
    assertThat(service.rotate(success.pair().wireToken()))
        .isInstanceOfSatisfying(
            RotateResult.Revoked.class, r -> assertThat(r.reason()).isEqualTo(RevokeReason.LOGOUT));
  }

  /** Successor's parent-link points back at the parent's refreshId. */
  public void rotationUpdatesFamilyChainAndChildLinksToParent() {
    RefreshTokenPair root = service.issue(USER, AUDIENCE, Optional.empty(), AMR);
    RotateResult.Success rotated = (RotateResult.Success) service.rotate(root.wireToken());

    List<String> familyIds = new ArrayList<>();
    for (var r : repository.findByFamilyId(root.record().familyId())) {
      familyIds.add(r.refreshId());
    }
    assertThat(familyIds).contains(root.record().refreshId(), rotated.pair().record().refreshId());
    assertThat(rotated.pair().record().parentRefreshId()).hasValue(root.record().refreshId());
  }

  /** Presenting a used token triggers a family scorch and returns Replayed. */
  public void replayOfUsedTokenScorchesEntireFamily() {
    RefreshTokenPair root = service.issue(USER, AUDIENCE, Optional.empty(), AMR);
    RotateResult.Success first = (RotateResult.Success) service.rotate(root.wireToken());
    // Re-present the root (already used) — replay defense.
    RotateResult replay = service.rotate(root.wireToken());
    assertThat(replay).isInstanceOf(RotateResult.Replayed.class);
    // Both rows in the family are now revoked.
    for (var r : repository.findByFamilyId(root.record().familyId())) {
      assertThat(r.revokedAt()).as("row %s revoked", r.refreshId()).isPresent();
      assertThat(r.revokedReason()).hasValue(RevokeReason.ROTATION_REPLAY);
    }
    // And the legitimate successor — which the attacker has no way to reach — is also now
    // revoked. The honest client sees Replayed on its next refresh and logs in. (The service
    // intentionally maps a ROTATION_REPLAY-scorched family to Replayed rather than Revoked so
    // race losers and replay-after-the-fact callers see a consistent outcome.)
    assertThat(service.rotate(first.pair().wireToken())).isInstanceOf(RotateResult.Replayed.class);
  }

  /** Past-due tokens return Expired without any family revocation. */
  public void expiredTokenRotationReturnsExpired() {
    // Issue at NOW, then build a service whose clock is 60 days later (default TTL is 14d).
    RefreshTokenPair root = service.issue(USER, AUDIENCE, Optional.empty(), AMR);
    RefreshTokenService laterService =
        new RefreshTokenService(
            repository,
            new RefreshTokenConfig(
                RefreshTtlPolicy.single(Duration.ofDays(14)), 32, 16, Duration.ofDays(30)),
            fixedClock(NOW.plus(Duration.ofDays(60))));
    assertThat(laterService.rotate(root.wireToken())).isInstanceOf(RotateResult.Expired.class);
    // No family revocation — expired is not a replay signal.
    for (var r : repository.findByFamilyId(root.record().familyId())) {
      assertThat(r.revokedAt()).as("row %s untouched", r.refreshId()).isEmpty();
    }
  }

  /** A wire token whose refreshId doesn't match any row returns Unknown. */
  public void unknownRefreshIdReturnsUnknown() {
    assertThat(service.rotate("nonExistentRefreshId.aaaa"))
        .isInstanceOf(RotateResult.Unknown.class);
  }

  /**
   * Presenting the right refreshId with the wrong secret returns Unknown — and crucially does NOT
   * mark the legitimate token used. This is the hash-before-mark-used invariant from ADR 0013.
   */
  public void wrongSecretReturnsUnknownAndDoesNotBurnLegitToken() {
    RefreshTokenPair root = service.issue(USER, AUDIENCE, Optional.empty(), AMR);
    String forged = root.record().refreshId() + ".wrongSecretBase64Url";
    assertThat(service.rotate(forged)).isInstanceOf(RotateResult.Unknown.class);
    // Legitimate rotation still works after the failed presentation.
    assertThat(service.rotate(root.wireToken())).isInstanceOf(RotateResult.Success.class);
  }

  /** Calling revokeFamily twice is a no-op the second time. */
  public void revokeFamilyIsIdempotent() {
    RefreshTokenPair root = service.issue(USER, AUDIENCE, Optional.empty(), AMR);
    service.revokeFamily(root.record().familyId(), RevokeReason.LOGOUT);
    service.revokeFamily(root.record().familyId(), RevokeReason.LOGOUT);
    var family = repository.findByFamilyId(root.record().familyId());
    assertThat(family).hasSize(1);
    assertThat(family.get(0).revokedReason()).hasValue(RevokeReason.LOGOUT);
  }

  /** revokeAllForUser scorches every family for the user but leaves other users intact. */
  public void revokeAllForUserRevokesEveryActiveFamily() {
    UserHandle alice = UserHandle.of(new byte[] {1});
    UserHandle bob = UserHandle.of(new byte[] {2});
    service.issue(alice, AUDIENCE, Optional.empty(), AMR);
    service.issue(alice, "cli", Optional.empty(), AMR);
    service.issue(bob, AUDIENCE, Optional.empty(), AMR);

    int revoked = service.revokeAllForUser(alice, RevokeReason.USER_DELETED);
    assertThat(revoked).isEqualTo(2);
    assertThat(repository.findByUserHandle(alice))
        .allSatisfy(r -> assertThat(r.revokedAt()).isPresent());
    assertThat(repository.findByUserHandle(bob))
        .allSatisfy(r -> assertThat(r.revokedAt()).isEmpty());
  }

  /**
   * The non-negotiable concurrent rotation race test. Eight threads all rotate the same root token
   * simultaneously: exactly one must win and the rest see {@link RotateResult.Replayed}. The entire
   * family — both the root AND any successor inserted by the winner — must end up revoked. Modeled
   * on motif's {@code concurrent_sameSecret_exactlyOneSucceeds_familyRevoked}.
   */
  public void concurrentRotationExactlyOneSucceedsFamilyRevoked() throws Exception {
    RefreshTokenPair root = service.issue(USER, AUDIENCE, Optional.empty(), AMR);

    int threads = 8;
    CountDownLatch ready = new CountDownLatch(threads);
    CountDownLatch fire = new CountDownLatch(1);
    List<Future<RotateResult>> futures = new ArrayList<>();
    try (ExecutorService pool = Executors.newFixedThreadPool(threads)) {
      for (int i = 0; i < threads; i++) {
        futures.add(
            pool.submit(
                () -> {
                  ready.countDown();
                  fire.await();
                  return service.rotate(root.wireToken());
                }));
      }
      assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
      fire.countDown();

      int success = 0;
      int replayed = 0;
      int other = 0;
      for (Future<RotateResult> f : futures) {
        RotateResult r = f.get(10, TimeUnit.SECONDS);
        if (r instanceof RotateResult.Success) {
          success++;
        } else if (r instanceof RotateResult.Replayed) {
          replayed++;
        } else {
          other++;
        }
      }

      assertThat(success).as("exactly one thread wins").isEqualTo(1);
      assertThat(replayed).as("rest see Replayed").isEqualTo(threads - 1);
      assertThat(other).as("no other outcomes").isZero();

      // Entire family is revoked — root AND the successor minted by the winner.
      var family = repository.findByFamilyId(root.record().familyId());
      assertThat(family).as("family contains root + successor").hasSizeGreaterThanOrEqualTo(2);
      assertThat(family)
          .allSatisfy(
              r -> assertThat(r.revokedAt()).as("row %s revoked", r.refreshId()).isPresent());
    }
  }

  // -- Helpers --------------------------------------------------------------------------

  private static ClockProvider fixedClock(Instant instant) {
    return ClockProvider.fromClock(Clock.fixed(instant, ZoneOffset.UTC));
  }
}
