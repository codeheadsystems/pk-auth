// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import com.codeheadsystems.pkauth.api.AssertionResult;
import com.codeheadsystems.pkauth.api.AttestationConveyance;
import com.codeheadsystems.pkauth.api.AuthenticationResponseJson;
import com.codeheadsystems.pkauth.api.AuthenticationResponseJson.AuthenticatorAssertionResponseJson;
import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson.AuthenticatorAttestationResponseJson;
import com.codeheadsystems.pkauth.api.RegistrationResult;
import com.codeheadsystems.pkauth.api.ResidentKeyRequirement;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResult;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResult;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.api.UserVerificationRequirement;
import com.codeheadsystems.pkauth.config.CeremonyConfig;
import com.codeheadsystems.pkauth.config.CounterRegressionPolicy;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.metrics.Metrics;
import com.codeheadsystems.pkauth.spi.AttestationTrustPolicy;
import com.codeheadsystems.pkauth.spi.CeremonyRateLimiter;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.OriginValidator;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.ObjectConverter;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Proves the {@link CeremonyRateLimiter} is consulted on every public entrypoint of {@link
 * DefaultPasskeyAuthenticationService} and that a refusal short-circuits the ceremony before any
 * challenge / credential interaction.
 */
class DefaultPasskeyAuthenticationServiceRateLimitTest {

  private static final Instant NOW = Instant.parse("2026-05-13T12:00:00Z");
  private static final ChallengeId CHALLENGE_ID = new ChallengeId("Y2hhbGxlbmdl");
  private static final UserHandle USER_HANDLE = UserHandle.of(new byte[16]);

  private WebAuthnManager webAuthnManager;
  private CredentialRepository credentialRepository;
  private UserLookup userLookup;
  private ChallengeStore challengeStore;
  private OriginValidator originValidator;
  private AttestationTrustPolicy attestationTrustPolicy;
  private Metrics metrics;
  private RecordingLimiter limiter;
  private DefaultPasskeyAuthenticationService service;

  @BeforeEach
  void setUp() {
    webAuthnManager = mock(WebAuthnManager.class);
    credentialRepository = mock(CredentialRepository.class);
    userLookup = mock(UserLookup.class);
    challengeStore = mock(ChallengeStore.class);
    originValidator = mock(OriginValidator.class);
    attestationTrustPolicy = mock(AttestationTrustPolicy.class);
    metrics = mock(Metrics.class);

    lenient()
        .when(attestationTrustPolicy.evaluate(any()))
        .thenReturn(new AttestationTrustPolicy.Decision.Trusted());
    lenient().when(userLookup.getOrCreateHandle(any())).thenReturn(USER_HANDLE);
    lenient().when(credentialRepository.findByUserHandle(any())).thenReturn(java.util.List.of());

    limiter = new RecordingLimiter();
    service = newService(limiter);
  }

  private DefaultPasskeyAuthenticationService newService(CeremonyRateLimiter rateLimiter) {
    RelyingPartyConfig rp =
        new RelyingPartyConfig("example.com", "Example", Set.of("https://example.com"));
    CeremonyConfig ceremonyConfig =
        new CeremonyConfig(
            Duration.ofMinutes(5),
            UserVerificationRequirement.PREFERRED,
            ResidentKeyRequirement.PREFERRED,
            AttestationConveyance.NONE,
            CounterRegressionPolicy.REJECT);
    SecureRandom random =
        new SecureRandom() {
          @Override
          public void nextBytes(byte[] bytes) {
            java.util.Arrays.fill(bytes, (byte) 0);
          }
        };
    return new DefaultPasskeyAuthenticationService(
        webAuthnManager,
        new ObjectConverter(),
        credentialRepository,
        userLookup,
        challengeStore,
        ClockProvider.fromClock(Clock.fixed(NOW, ZoneOffset.UTC)),
        originValidator,
        attestationTrustPolicy,
        rp,
        ceremonyConfig,
        new ChallengeGenerator(random),
        metrics,
        rateLimiter);
  }

  @Test
  void startRegistrationRefusedWhenIpBucketDenies() {
    limiter.denyIp = true;

    StartRegistrationResult result =
        service.startRegistration(
            new StartRegistrationRequest("alice", "Alice", null, null), "1.2.3.4");

    assertThat(result).isInstanceOf(StartRegistrationResult.RateLimited.class);
    assertThat(((StartRegistrationResult.RateLimited) result).bucket()).isEqualTo("ip");
    assertThat(limiter.ipCalls).containsExactly("1.2.3.4");
    assertThat(limiter.usernameCalls).isEmpty();
    verify(challengeStore, never()).put(any(), any(), any());
  }

  @Test
  void startRegistrationRefusedWhenUsernameBucketDenies() {
    limiter.denyUsername = true;

    StartRegistrationResult result =
        service.startRegistration(
            new StartRegistrationRequest("alice", "Alice", null, null), "1.2.3.4");

    assertThat(result).isInstanceOf(StartRegistrationResult.RateLimited.class);
    assertThat(((StartRegistrationResult.RateLimited) result).bucket()).isEqualTo("username");
    assertThat(limiter.ipCalls).containsExactly("1.2.3.4");
    assertThat(limiter.usernameCalls).containsExactly("alice");
    verify(challengeStore, never()).put(any(), any(), any());
  }

  @Test
  void startAuthenticationRefusedWhenIpBucketDenies() {
    limiter.denyIp = true;

    StartAuthenticationResult result =
        service.startAuthentication(new StartAuthenticationRequest("alice", null), "9.9.9.9");

    assertThat(result).isInstanceOf(StartAuthenticationResult.RateLimited.class);
    verify(challengeStore, never()).put(any(), any(), any());
  }

  @Test
  void finishRegistrationReturnsRateLimitedVariant() {
    limiter.denyIp = true;

    RegistrationResult result = service.finishRegistration(stubFinishRegistration(), "5.5.5.5");

    assertThat(result).isInstanceOf(RegistrationResult.RateLimited.class);
    assertThat(((RegistrationResult.RateLimited) result).bucket()).isEqualTo("ip");
    assertThat(limiter.ipCalls).containsExactly("5.5.5.5");
    verify(credentialRepository, never()).save(any());
  }

  @Test
  void finishAuthenticationReturnsRateLimitedVariant() {
    limiter.denyIp = true;

    AssertionResult result = service.finishAuthentication(stubFinishAuthentication(), "5.5.5.5");

    assertThat(result).isInstanceOf(AssertionResult.RateLimited.class);
    assertThat(((AssertionResult.RateLimited) result).bucket()).isEqualTo("ip");
    assertThat(limiter.ipCalls).containsExactly("5.5.5.5");
    verify(credentialRepository, never()).findByCredentialId(any());
  }

  @Test
  void allowedCallsConsultLimiterAndProceed() {
    service.startRegistration(
        new StartRegistrationRequest("alice", "Alice", null, null), "1.2.3.4");

    assertThat(limiter.ipCalls).containsExactly("1.2.3.4");
    assertThat(limiter.usernameCalls).containsExactly("alice");
    verify(challengeStore).put(any(), any(), any());
  }

  private static FinishRegistrationRequest stubFinishRegistration() {
    return new FinishRegistrationRequest(
        CHALLENGE_ID,
        "alice",
        null,
        new RegistrationResponseJson(
            new byte[] {1, 2},
            new byte[] {1, 2},
            new AuthenticatorAttestationResponseJson(
                new byte[0], new byte[0], null, null, null, null),
            null,
            null,
            "public-key"));
  }

  private static FinishAuthenticationRequest stubFinishAuthentication() {
    return new FinishAuthenticationRequest(
        CHALLENGE_ID,
        new AuthenticationResponseJson(
            new byte[] {1, 2},
            new byte[] {1, 2},
            new AuthenticatorAssertionResponseJson(new byte[0], new byte[0], new byte[0], null),
            null,
            null,
            "public-key"));
  }

  private static final class RecordingLimiter implements CeremonyRateLimiter {
    boolean denyIp = false;
    boolean denyUsername = false;
    final List<String> ipCalls = new ArrayList<>();
    final List<String> usernameCalls = new ArrayList<>();

    @Override
    public boolean tryAcquireForIp(@Nullable String ip) {
      ipCalls.add(ip);
      return !denyIp;
    }

    @Override
    public boolean tryAcquireForUsername(String username) {
      usernameCalls.add(username);
      return !denyUsername;
    }
  }
}
