// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.jwt.JwtConfig;
import com.codeheadsystems.pkauth.jwt.JwtKeyset;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.refresh.RefreshTokenConfig;
import com.codeheadsystems.pkauth.refresh.RefreshTokenPair;
import com.codeheadsystems.pkauth.refresh.RefreshTokenService;
import com.codeheadsystems.pkauth.refresh.RevokeReason;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.testkit.InMemoryRefreshTokenRepository;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Exercises every {@link RefreshHandler.Outcome} branch plus the null/blank-request guard. */
class RefreshHandlerTest {

  private static final Instant NOW = Instant.parse("2026-05-16T12:00:00Z");
  private static final UserHandle USER = UserHandle.of(new byte[] {1, 2, 3});
  private static final String AUDIENCE = "web";
  private static final List<String> AMR = List.of("pkauth", "webauthn");

  private InMemoryRefreshTokenRepository repository;
  private RefreshTokenService service;
  private RefreshHandler handler;

  @BeforeEach
  void setUp() {
    repository = new InMemoryRefreshTokenRepository();
    ClockProvider clock = ClockProvider.fromClock(Clock.fixed(NOW, ZoneOffset.UTC));
    service =
        new RefreshTokenService(
            repository, RefreshTokenConfig.defaults(), clock, new SecureRandom());
    PkAuthJwtIssuer issuer =
        new PkAuthJwtIssuer(
            JwtConfig.defaults("https://pkauth.example.com", AUDIENCE),
            JwtKeyset.hs256(new byte[32]),
            clock);
    handler = new RefreshHandler(service, issuer);
  }

  @Test
  void nullRequestBecomesUnknownFailure() {
    assertFailure(handler.handle(null), "unknown", null);
  }

  @Test
  void nullTokenBecomesUnknownFailure() {
    assertFailure(handler.handle(new RefreshRequest(null)), "unknown", null);
  }

  @Test
  void blankTokenBecomesUnknownFailure() {
    assertFailure(handler.handle(new RefreshRequest("   ")), "unknown", null);
  }

  @Test
  void successMintsAccessJwtAndReturnsRotatedRefreshToken() {
    RefreshTokenPair root = service.issue(USER, AUDIENCE, Optional.empty(), AMR);
    RefreshHandler.Outcome outcome = handler.handle(new RefreshRequest(root.wireToken()));

    assertThat(outcome).isInstanceOf(RefreshHandler.Outcome.Success.class);
    RefreshResponse response = ((RefreshHandler.Outcome.Success) outcome).response();
    assertThat(response.refreshToken()).isNotEqualTo(root.wireToken()).contains(".");
    assertThat(response.accessToken()).isNotBlank();
    assertThat(response.accessToken().split("\\.")).hasSize(3); // header.payload.signature
    assertThat(response.expiresAt()).isAfter(NOW);
  }

  @Test
  void unknownTokenIsUnknownFailure() {
    assertFailure(handler.handle(new RefreshRequest("missing.aaaa")), "unknown", null);
  }

  @Test
  void expiredTokenIsExpiredFailure() {
    RefreshTokenPair root = service.issue(USER, AUDIENCE, Optional.empty(), AMR);
    PkAuthJwtIssuer issuer =
        new PkAuthJwtIssuer(
            JwtConfig.defaults("https://pkauth.example.com", AUDIENCE),
            JwtKeyset.hs256(new byte[32]),
            ClockProvider.fromClock(Clock.fixed(NOW, ZoneOffset.UTC)));
    RefreshTokenService later =
        new RefreshTokenService(
            repository,
            RefreshTokenConfig.defaults(),
            ClockProvider.fromClock(Clock.fixed(NOW.plus(Duration.ofDays(60)), ZoneOffset.UTC)),
            new SecureRandom());
    RefreshHandler laterHandler = new RefreshHandler(later, issuer);
    assertFailure(laterHandler.handle(new RefreshRequest(root.wireToken())), "expired", null);
  }

  @Test
  void replayedTokenIsReplayedFailure() {
    RefreshTokenPair root = service.issue(USER, AUDIENCE, Optional.empty(), AMR);
    handler.handle(new RefreshRequest(root.wireToken())); // first use succeeds
    assertFailure(handler.handle(new RefreshRequest(root.wireToken())), "replayed", null);
  }

  @Test
  void revokedTokenIsRevokedFailureCarryingReason() {
    RefreshTokenPair root = service.issue(USER, AUDIENCE, Optional.empty(), AMR);
    service.revokeFamily(root.record().familyId(), RevokeReason.LOGOUT);
    assertFailure(handler.handle(new RefreshRequest(root.wireToken())), "revoked", "LOGOUT");
  }

  @Test
  void constructorRejectsNullDependencies() {
    PkAuthJwtIssuer issuer =
        new PkAuthJwtIssuer(
            JwtConfig.defaults("https://pkauth.example.com", AUDIENCE),
            JwtKeyset.hs256(new byte[32]),
            ClockProvider.fromClock(Clock.fixed(NOW, ZoneOffset.UTC)));
    assertThatThrownBy(() -> new RefreshHandler(null, issuer))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new RefreshHandler(service, null))
        .isInstanceOf(NullPointerException.class);
  }

  private static void assertFailure(RefreshHandler.Outcome outcome, String detail, String reason) {
    assertThat(outcome).isInstanceOf(RefreshHandler.Outcome.Failure.class);
    RefreshErrorResponse response = ((RefreshHandler.Outcome.Failure) outcome).response();
    assertThat(response.detail()).isEqualTo(detail);
    assertThat(response.reason()).isEqualTo(reason);
  }
}
