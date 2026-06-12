// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.magiclink;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.jwt.JwtConfig;
import com.codeheadsystems.pkauth.jwt.JwtKeyset;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.testkit.InMemoryUserLookup;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class MagicLinkServiceTest {

  private static final Instant NOW = Instant.parse("2026-05-14T12:00:00Z");
  private static final String ISSUER = "https://pkauth.example.com";
  private static final String AUDIENCE = "https://app.example.com";
  private static final String BASE_URL = "https://app.example.com/auth/magic";

  private InMemoryUserLookup users;
  private RecordingEmailSender emails;
  private MagicLinkService service;

  @BeforeEach
  void setUp() {
    users = new InMemoryUserLookup();
    emails = new RecordingEmailSender();
    byte[] secret = new byte[32];
    new SecureRandom().nextBytes(secret);
    JwtKeyset keyset = JwtKeyset.hs256(secret);
    JwtConfig config = JwtConfig.defaults(ISSUER, AUDIENCE);
    ClockProvider clock = ClockProvider.fromClock(Clock.fixed(NOW, ZoneOffset.UTC));
    service =
        MagicLinkService.create(
            MagicLinkService.Dependencies.of(
                new PkAuthJwtIssuer(config, keyset, clock),
                new PkAuthJwtValidator(config, keyset, clock),
                emails,
                users,
                clock),
            new MagicLinkService.Config(
                BASE_URL,
                5,
                new MagicLinkService.InMemoryRateLimiter(Duration.ofHours(1)),
                MagicLinkService.DEFAULT_CONSUMED_JTI_TTL));
  }

  @Test
  void configRejectsNonPositiveRanges() {
    MagicLinkService.InMemoryRateLimiter limiter =
        new MagicLinkService.InMemoryRateLimiter(Duration.ofHours(1));
    assertThatThrownBy(
            () -> new MagicLinkService.Config(BASE_URL, 0, limiter, Duration.ofMinutes(30)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("rateLimit");
    assertThatThrownBy(() -> new MagicLinkService.Config(BASE_URL, 5, limiter, Duration.ZERO))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("consumedJtiTtl");
  }

  @Test
  void verificationEmailDispatchesAndTokenConsumesOnce() {
    UserHandle user = UserHandle.random();
    MagicLinkService.SendResult send = service.startEmailVerification(user, "alice@example.com");
    assertThat(send).isInstanceOf(MagicLinkService.SendResult.Sent.class);
    String token = ((MagicLinkService.SendResult.Sent) send).tokenJti();
    assertThat(emails.sent).hasSize(1);
    assertThat(emails.sent.get(0).subject).isEqualTo("Verify your email");

    MagicLinkService.ConsumeResult consumed = service.finishVerification(token);
    assertThat(consumed)
        .isInstanceOfSatisfying(
            MagicLinkService.ConsumeResult.Success.class,
            s -> {
              assertThat(s.purpose()).isEqualTo(MagicLinkService.PURPOSE_EMAIL_VERIFY);
              assertThat(s.email()).isEqualTo("alice@example.com");
              assertThat(s.userHandle()).isEqualTo(user);
            });

    // Single-use: consuming the same token again must fail.
    assertThat(service.finishVerification(token))
        .isInstanceOf(MagicLinkService.ConsumeResult.AlreadyConsumed.class);
  }

  @Test
  void loginEmailRoundTrip() {
    UserHandle user = users.register("alice", "Alice");

    MagicLinkService.SendResult send = service.startLogin("alice", "alice@example.com");
    String token = ((MagicLinkService.SendResult.Sent) send).tokenJti();
    assertThat(emails.sent.get(0).subject).isEqualTo("Sign in");

    MagicLinkService.ConsumeResult consumed = service.finishVerification(token);
    assertThat(consumed)
        .isInstanceOfSatisfying(
            MagicLinkService.ConsumeResult.Success.class,
            s -> {
              assertThat(s.purpose()).isEqualTo(MagicLinkService.PURPOSE_LOGIN);
              assertThat(s.userHandle()).isEqualTo(user);
            });
  }

  @Test
  void loginUnknownUserReturnsSentToPreventEnumeration() {
    // Privacy invariant: startLogin must return Sent even when the username does not exist,
    // so callers cannot enumerate accounts via the result shape.
    MagicLinkService.SendResult result = service.startLogin("nobody", "n@example.com");
    assertThat(result).isInstanceOf(MagicLinkService.SendResult.Sent.class);
    // No email must have been dispatched for an unknown user.
    assertThat(emails.sent).isEmpty();
  }

  @Test
  void rateLimitsAfterConfiguredCount() {
    UserHandle user = UserHandle.random();
    for (int i = 0; i < 5; i++) {
      service.startEmailVerification(user, "a@example.com");
    }
    assertThat(service.startEmailVerification(user, "a@example.com"))
        .isInstanceOf(MagicLinkService.SendResult.RateLimited.class);
  }

  @Test
  void tamperedTokenRejected() {
    UserHandle user = UserHandle.random();
    MagicLinkService.SendResult send = service.startEmailVerification(user, "a@example.com");
    String token = ((MagicLinkService.SendResult.Sent) send).tokenJti();
    String tampered = token.substring(0, token.length() - 4) + "AAAA";
    assertThat(service.finishVerification(tampered))
        .isInstanceOf(MagicLinkService.ConsumeResult.Invalid.class);
  }

  /** Captures emails for inspection. */
  private static final class RecordingEmailSender implements EmailSender {
    private final List<Sent> sent = new ArrayList<>();

    @Override
    public void send(String to, String subject, String body) {
      sent.add(new Sent(to, subject, body));
    }

    record Sent(String to, String subject, String body) {}
  }
}
