// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class ChallengeRecordTest {

  @Test
  void buildsAndCopiesChallenge() {
    byte[] raw = {1, 2, 3};
    Instant exp = Instant.parse("2024-01-01T00:05:00Z");
    UserHandle uh = UserHandle.random();
    ChallengeRecord rec = new ChallengeRecord(raw, ChallengeRecord.Purpose.REGISTRATION, uh, exp);

    raw[0] = 99;
    assertThat(rec.challenge()[0]).isEqualTo((byte) 1);
    assertThat(rec.purpose()).isEqualTo(ChallengeRecord.Purpose.REGISTRATION);
    assertThat(rec.userHandle()).isEqualTo(uh);
    assertThat(rec.expiresAt()).isEqualTo(exp);
  }

  @Test
  void equalsAndHashCode() {
    Instant exp = Instant.parse("2024-01-01T00:05:00Z");
    UserHandle uh = UserHandle.of(new byte[] {7});
    ChallengeRecord a =
        new ChallengeRecord(new byte[] {1, 2}, ChallengeRecord.Purpose.ASSERTION, uh, exp);
    ChallengeRecord b =
        new ChallengeRecord(new byte[] {1, 2}, ChallengeRecord.Purpose.ASSERTION, uh, exp);
    ChallengeRecord c =
        new ChallengeRecord(new byte[] {1, 3}, ChallengeRecord.Purpose.ASSERTION, uh, exp);
    assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    assertThat(a).isNotEqualTo(c);
    assertThat(a).isNotEqualTo("nope");
  }

  @Test
  void rejectsEmptyChallenge() {
    assertThatThrownBy(
            () ->
                new ChallengeRecord(
                    new byte[0], ChallengeRecord.Purpose.REGISTRATION, null, Instant.now()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void purposeEnumValues() {
    assertThat(ChallengeRecord.Purpose.values())
        .containsExactly(ChallengeRecord.Purpose.REGISTRATION, ChallengeRecord.Purpose.ASSERTION);
  }
}
