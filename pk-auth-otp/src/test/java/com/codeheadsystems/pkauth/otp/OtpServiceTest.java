// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.otp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.testkit.InMemoryOtpRepository;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class OtpServiceTest {

  private static final Instant NOW = Instant.parse("2026-05-14T12:00:00Z");
  private static final UserHandle USER = UserHandle.of(new byte[] {1, 2, 3});
  private static final String PHONE = "+15551234567";

  /** 32-byte fixed pepper for tests. */
  private static final byte[] TEST_PEPPER = new byte[32];

  static {
    // Fill with deterministic non-zero bytes so tests are reproducible.
    for (int i = 0; i < TEST_PEPPER.length; i++) {
      TEST_PEPPER[i] = (byte) (i + 1);
    }
  }

  private InMemoryOtpRepository repository;
  private RecordingSmsSender sms;
  private OtpService service;

  @BeforeEach
  void setUp() {
    repository = new InMemoryOtpRepository();
    sms = new RecordingSmsSender();
    service =
        OtpService.create(
            OtpService.Dependencies.of(
                repository, sms, ClockProvider.fromClock(Clock.fixed(NOW, ZoneOffset.UTC))),
            new OtpService.Config(
                new SecureRandom(),
                TEST_PEPPER,
                Duration.ofMinutes(5),
                3,
                3,
                Duration.ofMinutes(15)));
  }

  @Test
  void sendIssuesAndDispatchesCode() {
    OtpService.SendResult result = service.startVerification(USER, PHONE);
    assertThat(result).isInstanceOf(OtpService.SendResult.Sent.class);
    assertThat(sms.messages).hasSize(1);
    assertThat(sms.messages.get(0).message).contains("verification code");
  }

  @Test
  void verifyAcceptsMatchingCodeOnce() {
    service.startVerification(USER, PHONE);
    String code = sms.lastCode();

    assertThat(service.finishVerification(USER, PHONE, code))
        .isInstanceOf(OtpService.VerifyResult.Success.class);
    // After consume, no active OTP.
    assertThat(service.finishVerification(USER, PHONE, code))
        .isInstanceOf(OtpService.VerifyResult.NoActiveOtp.class);
  }

  @Test
  void verifyMismatchDecrementsRemainingAttempts() {
    service.startVerification(USER, PHONE);
    OtpService.VerifyResult first = service.finishVerification(USER, PHONE, "000000");
    assertThat(first)
        .isInstanceOfSatisfying(
            OtpService.VerifyResult.CodeMismatch.class,
            m -> assertThat(m.remainingAttempts()).isEqualTo(2));
    service.finishVerification(USER, PHONE, "000000");
    service.finishVerification(USER, PHONE, "000000");
    assertThat(service.finishVerification(USER, PHONE, "000000"))
        .isInstanceOf(OtpService.VerifyResult.AttemptsExceeded.class);
  }

  @Test
  void sendRateLimits() {
    service.startVerification(USER, PHONE);
    service.startVerification(USER, PHONE);
    service.startVerification(USER, PHONE);
    assertThat(service.startVerification(USER, PHONE))
        .isInstanceOfSatisfying(
            OtpService.SendResult.RateLimited.class,
            r -> assertThat(r.countInWindow()).isGreaterThanOrEqualTo(3));
  }

  @Test
  void expiredOtpIsRejected() {
    service.startVerification(USER, PHONE);
    String code = sms.lastCode();
    OtpService advanced =
        OtpService.create(
            OtpService.Dependencies.of(
                repository,
                sms,
                ClockProvider.fromClock(
                    Clock.fixed(NOW.plus(Duration.ofMinutes(10)), ZoneOffset.UTC))),
            new OtpService.Config(
                new SecureRandom(),
                TEST_PEPPER,
                Duration.ofMinutes(5),
                3,
                3,
                Duration.ofMinutes(15)));
    assertThat(advanced.finishVerification(USER, PHONE, code))
        .isInstanceOf(OtpService.VerifyResult.Expired.class);
  }

  @Test
  void maskPhoneKeepsCountryPrefixAndLast4() {
    // Normal E.164 numbers: keep '+' + first country digit + '***' + last 4 digits.
    assertThat(OtpService.maskPhone("+15551234567")).isEqualTo("+1***4567");
    assertThat(OtpService.maskPhone("+441234567890")).isEqualTo("+4***7890");
    assertThat(OtpService.maskPhone("+3531234567")).isEqualTo("+3***4567");
    // Short / edge-case inputs that cannot provide a meaningful masked form.
    assertThat(OtpService.maskPhone("+12345")).isEqualTo("+***"); // < 7 chars
    assertThat(OtpService.maskPhone("+1")).isEqualTo("+***");
    assertThat(OtpService.maskPhone(null)).isEqualTo("+***");
    assertThat(OtpService.maskPhone("abc")).isEqualTo("+***");
  }

  @Test
  void configRejectsNonPositiveRangesAndShortPepper() {
    SecureRandom rng = new SecureRandom();
    assertThatThrownBy(
            () ->
                new OtpService.Config(
                    rng, new byte[8], Duration.ofMinutes(5), 3, 3, Duration.ofMinutes(15)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("pepper");
    assertThatThrownBy(
            () ->
                new OtpService.Config(
                    rng, TEST_PEPPER, Duration.ZERO, 3, 3, Duration.ofMinutes(15)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("ttl");
    assertThatThrownBy(
            () ->
                new OtpService.Config(
                    rng, TEST_PEPPER, Duration.ofMinutes(5), 0, 3, Duration.ofMinutes(15)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("maxAttempts");
    assertThatThrownBy(
            () ->
                new OtpService.Config(
                    rng, TEST_PEPPER, Duration.ofMinutes(5), 3, 0, Duration.ofMinutes(15)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("rateLimit");
    assertThatThrownBy(
            () ->
                new OtpService.Config(rng, TEST_PEPPER, Duration.ofMinutes(5), 3, 3, Duration.ZERO))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("rateWindow");
  }

  /** Captures sends so tests can pluck the dispatched code out of the message body. */
  private static final class RecordingSmsSender implements SmsSender {
    private final List<Sent> messages = new ArrayList<>();

    @Override
    public void send(String phoneE164, String body) {
      messages.add(new Sent(phoneE164, body));
    }

    String lastCode() {
      String last = messages.get(messages.size() - 1).message;
      // Pull the trailing token off "Your verification code is XXXXXX".
      int idx = last.lastIndexOf(' ');
      return last.substring(idx + 1);
    }

    record Sent(String phone, String message) {}
  }
}
