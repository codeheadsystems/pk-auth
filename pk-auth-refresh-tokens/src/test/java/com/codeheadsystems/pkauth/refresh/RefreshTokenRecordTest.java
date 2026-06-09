// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * Compact-constructor validation, defensive copies, and equality for {@link RefreshTokenRecord}.
 */
class RefreshTokenRecordTest {

  private static final UserHandle USER = UserHandle.of(new byte[] {1, 2, 3});
  private static final Instant NOW = Instant.parse("2026-05-16T12:00:00Z");

  /** Builds a valid root record, overriding nothing. */
  private static RefreshTokenRecord valid() {
    return new RefreshTokenRecord(
        "rid",
        new byte[] {1, 2, 3, 4},
        USER,
        "web",
        Optional.empty(),
        "rid",
        Optional.empty(),
        NOW,
        NOW.plusSeconds(3600),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        List.of("pkauth"));
  }

  @Test
  void validRecordRoundTrips() {
    RefreshTokenRecord r = valid();
    assertThat(r.refreshId()).isEqualTo("rid");
    assertThat(r.audience()).isEqualTo("web");
    assertThat(r.amr()).containsExactly("pkauth");
  }

  @Test
  void rejectsBlankRefreshId() {
    assertThatThrownBy(
            () ->
                new RefreshTokenRecord(
                    "  ",
                    new byte[] {1},
                    USER,
                    "web",
                    Optional.empty(),
                    "fam",
                    Optional.empty(),
                    NOW,
                    NOW,
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    List.of("a")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("refreshId");
  }

  @Test
  void rejectsEmptyTokenHash() {
    assertThatThrownBy(
            () ->
                new RefreshTokenRecord(
                    "rid",
                    new byte[0],
                    USER,
                    "web",
                    Optional.empty(),
                    "fam",
                    Optional.empty(),
                    NOW,
                    NOW,
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    List.of("a")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("tokenHash");
  }

  @Test
  void rejectsBlankAudience() {
    assertThatThrownBy(
            () ->
                new RefreshTokenRecord(
                    "rid",
                    new byte[] {1},
                    USER,
                    " ",
                    Optional.empty(),
                    "fam",
                    Optional.empty(),
                    NOW,
                    NOW,
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    List.of("a")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("audience");
  }

  @Test
  void rejectsBlankFamilyId() {
    assertThatThrownBy(
            () ->
                new RefreshTokenRecord(
                    "rid",
                    new byte[] {1},
                    USER,
                    "web",
                    Optional.empty(),
                    " ",
                    Optional.empty(),
                    NOW,
                    NOW,
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    List.of("a")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("familyId");
  }

  @Test
  void rejectsRevokedAtWithoutReason() {
    assertThatThrownBy(
            () ->
                new RefreshTokenRecord(
                    "rid",
                    new byte[] {1},
                    USER,
                    "web",
                    Optional.empty(),
                    "fam",
                    Optional.empty(),
                    NOW,
                    NOW,
                    Optional.empty(),
                    Optional.of(NOW),
                    Optional.empty(),
                    List.of("a")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("revokedAt and revokedReason");
  }

  @Test
  void rejectsReasonWithoutRevokedAt() {
    assertThatThrownBy(
            () ->
                new RefreshTokenRecord(
                    "rid",
                    new byte[] {1},
                    USER,
                    "web",
                    Optional.empty(),
                    "fam",
                    Optional.empty(),
                    NOW,
                    NOW,
                    Optional.empty(),
                    Optional.empty(),
                    Optional.of(RevokeReason.ADMIN),
                    List.of("a")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("revokedAt and revokedReason");
  }

  @Test
  void rejectsEmptyAmr() {
    assertThatThrownBy(
            () ->
                new RefreshTokenRecord(
                    "rid",
                    new byte[] {1},
                    USER,
                    "web",
                    Optional.empty(),
                    "fam",
                    Optional.empty(),
                    NOW,
                    NOW,
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    List.of()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("amr must be non-empty");
  }

  @Test
  void rejectsBlankAmrEntry() {
    assertThatThrownBy(
            () ->
                new RefreshTokenRecord(
                    "rid",
                    new byte[] {1},
                    USER,
                    "web",
                    Optional.empty(),
                    "fam",
                    Optional.empty(),
                    NOW,
                    NOW,
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    List.of(" ")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("amr entries must be non-blank");
  }

  @Test
  void rejectsAmrEntryWithComma() {
    assertThatThrownBy(
            () ->
                new RefreshTokenRecord(
                    "rid",
                    new byte[] {1},
                    USER,
                    "web",
                    Optional.empty(),
                    "fam",
                    Optional.empty(),
                    NOW,
                    NOW,
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    List.of("a,b")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must not contain ','");
  }

  @Test
  void tokenHashAccessorReturnsDefensiveCopy() {
    byte[] source = {9, 8, 7};
    RefreshTokenRecord r =
        new RefreshTokenRecord(
            "rid",
            source,
            USER,
            "web",
            Optional.empty(),
            "fam",
            Optional.empty(),
            NOW,
            NOW,
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            List.of("a"));
    source[0] = 0; // mutating the source must not affect the stored copy
    byte[] got = r.tokenHash();
    assertThat(got).containsExactly(9, 8, 7);
    got[0] = 0; // mutating the returned array must not affect the stored copy either
    assertThat(r.tokenHash()).containsExactly(9, 8, 7);
  }

  @Test
  void equalsAndHashCodeComparePerFieldIncludingHashContents() {
    RefreshTokenRecord a = valid();
    RefreshTokenRecord b = valid();
    assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    assertThat(a).isNotEqualTo(null).isNotEqualTo("not a record");

    // A differing tokenHash (array content) breaks equality — the record uses Arrays.equals.
    RefreshTokenRecord differentHash =
        new RefreshTokenRecord(
            "rid",
            new byte[] {9, 9, 9, 9},
            USER,
            "web",
            Optional.empty(),
            "rid",
            Optional.empty(),
            NOW,
            NOW.plusSeconds(3600),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            List.of("pkauth"));
    assertThat(a).isNotEqualTo(differentHash);

    // A differing scalar field also breaks equality.
    RefreshTokenRecord differentAudience =
        new RefreshTokenRecord(
            "rid",
            new byte[] {1, 2, 3, 4},
            USER,
            "cli",
            Optional.empty(),
            "rid",
            Optional.empty(),
            NOW,
            NOW.plusSeconds(3600),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            List.of("pkauth"));
    assertThat(a).isNotEqualTo(differentAudience);
  }
}
