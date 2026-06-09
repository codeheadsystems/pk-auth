// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** Validation and projection guards for the refresh DTO records. */
class RefreshRecordsTest {

  private static final UserHandle USER = UserHandle.of(new byte[] {1, 2, 3});
  private static final Instant NOW = Instant.parse("2026-05-16T12:00:00Z");

  @Test
  void rotatedClaimsRejectsEmptyAmr() {
    assertThatThrownBy(() -> new RotatedClaims(USER, "web", Optional.empty(), List.of()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("amr");
  }

  @Test
  void rotatedClaimsRejectsNullArguments() {
    List<String> amr = List.of("user");
    assertThatThrownBy(() -> new RotatedClaims(null, "web", Optional.empty(), amr))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new RotatedClaims(USER, null, Optional.empty(), amr))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new RotatedClaims(USER, "web", null, amr))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new RotatedClaims(USER, "web", Optional.empty(), null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void rotatedClaimsCopiesAmrDefensively() {
    List<String> mutable = new ArrayList<>(List.of("pkauth"));
    RotatedClaims claims = new RotatedClaims(USER, "web", Optional.empty(), mutable);
    mutable.add("tampered");
    assertThat(claims.amr()).containsExactly("pkauth");
  }

  @Test
  void summaryFromCopiesEveryNonSecretFieldAndDropsHashAndParent() {
    RefreshTokenRecord record =
        new RefreshTokenRecord(
            "rid-1",
            new byte[] {1, 2, 3, 4},
            USER,
            "web",
            Optional.of("dev-9"),
            "fam-1",
            Optional.of("parent-0"),
            NOW,
            NOW.plusSeconds(3600),
            Optional.of(NOW.plusSeconds(10)),
            Optional.of(NOW.plusSeconds(20)),
            Optional.of(RevokeReason.LOGOUT),
            List.of("pkauth"));

    RefreshTokenSummary summary = RefreshTokenSummary.from(record);

    assertThat(summary.refreshId()).isEqualTo("rid-1");
    assertThat(summary.audience()).isEqualTo("web");
    assertThat(summary.familyId()).isEqualTo("fam-1");
    assertThat(summary.deviceId()).hasValue("dev-9");
    assertThat(summary.issuedAt()).isEqualTo(NOW);
    assertThat(summary.expiresAt()).isEqualTo(NOW.plusSeconds(3600));
    assertThat(summary.usedAt()).hasValue(NOW.plusSeconds(10));
    assertThat(summary.revokedAt()).hasValue(NOW.plusSeconds(20));
  }

  @Test
  void summaryFromRejectsNullRecord() {
    assertThatThrownBy(() -> RefreshTokenSummary.from(null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void summaryConstructorRejectsNullFields() {
    assertThatThrownBy(
            () ->
                new RefreshTokenSummary(
                    null,
                    "web",
                    "fam",
                    Optional.empty(),
                    NOW,
                    NOW,
                    Optional.empty(),
                    Optional.empty()))
        .isInstanceOf(NullPointerException.class);
  }
}
