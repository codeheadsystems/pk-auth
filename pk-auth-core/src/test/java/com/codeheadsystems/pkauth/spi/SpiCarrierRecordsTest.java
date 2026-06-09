// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * Validation guards for the SPI-declared carrier records {@code StoredOtp} / {@code
 * StoredBackupCode}.
 */
class SpiCarrierRecordsTest {

  private static final UserHandle USER = UserHandle.of(new byte[] {1, 2, 3});
  private static final Instant NOW = Instant.parse("2026-05-16T12:00:00Z");

  // -- StoredOtp ----------------------------------------------------------------------------

  private static OtpRepository.StoredOtp validOtp(int attempts, int maxAttempts) {
    return new OtpRepository.StoredOtp(
        "otp-1",
        USER,
        "+15551234567",
        "hash",
        attempts,
        maxAttempts,
        false,
        NOW,
        NOW.plusSeconds(60));
  }

  @Test
  void storedOtpExposesAllFields() {
    OtpRepository.StoredOtp otp = validOtp(1, 5);
    assertThat(otp.otpId()).isEqualTo("otp-1");
    assertThat(otp.userHandle()).isEqualTo(USER);
    assertThat(otp.phoneE164()).isEqualTo("+15551234567");
    assertThat(otp.hashedCode()).isEqualTo("hash");
    assertThat(otp.attempts()).isEqualTo(1);
    assertThat(otp.maxAttempts()).isEqualTo(5);
    assertThat(otp.consumed()).isFalse();
    assertThat(otp.expiresAt()).isEqualTo(NOW.plusSeconds(60));
  }

  @Test
  void storedOtpRejectsNullRequiredFields() {
    assertThatThrownBy(
            () -> new OtpRepository.StoredOtp(null, USER, "+1", "h", 0, 1, false, NOW, NOW))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(
            () -> new OtpRepository.StoredOtp("id", null, "+1", "h", 0, 1, false, NOW, NOW))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(
            () -> new OtpRepository.StoredOtp("id", USER, null, "h", 0, 1, false, NOW, NOW))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(
            () -> new OtpRepository.StoredOtp("id", USER, "+1", null, 0, 1, false, NOW, NOW))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(
            () -> new OtpRepository.StoredOtp("id", USER, "+1", "h", 0, 1, false, null, NOW))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(
            () -> new OtpRepository.StoredOtp("id", USER, "+1", "h", 0, 1, false, NOW, null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void storedOtpRejectsNegativeAttemptsAndNonPositiveMax() {
    assertThatThrownBy(() -> validOtp(-1, 5))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("attempts");
    assertThatThrownBy(() -> validOtp(0, 0))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("maxAttempts");
  }

  // -- StoredBackupCode ---------------------------------------------------------------------

  @Test
  void storedBackupCodeExposesFieldsAndAllowsNullConsumedAt() {
    BackupCodeRepository.StoredBackupCode code =
        new BackupCodeRepository.StoredBackupCode("c-1", USER, "hash", false, NOW, null);
    assertThat(code.codeId()).isEqualTo("c-1");
    assertThat(code.userHandle()).isEqualTo(USER);
    assertThat(code.hashedCode()).isEqualTo("hash");
    assertThat(code.consumed()).isFalse();
    assertThat(code.createdAt()).isEqualTo(NOW);
    assertThat(code.consumedAt()).isNull();
  }

  @Test
  void storedBackupCodeRejectsNullRequiredFields() {
    assertThatThrownBy(
            () -> new BackupCodeRepository.StoredBackupCode(null, USER, "h", false, NOW, null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(
            () -> new BackupCodeRepository.StoredBackupCode("id", null, "h", false, NOW, null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(
            () -> new BackupCodeRepository.StoredBackupCode("id", USER, null, false, NOW, null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(
            () -> new BackupCodeRepository.StoredBackupCode("id", USER, "h", false, null, null))
        .isInstanceOf(NullPointerException.class);
  }
}
