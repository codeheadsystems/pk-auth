// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Compact-constructor guards, defensive copies, factories, and value semantics of {@link
 * JwtClaims}.
 */
class JwtClaimsTest {

  private static final UserHandle USER = UserHandle.of(new byte[] {1, 2, 3});

  @Test
  void factoriesSetExpectedMethodAndAudience() {
    assertThat(JwtClaims.forPasskey(USER, new byte[] {9}, List.of("u")).method())
        .isEqualTo(AuthMethod.PASSKEY);
    assertThat(JwtClaims.forBackupCode(USER, List.of("u")).method())
        .isEqualTo(AuthMethod.BACKUP_CODE);
    assertThat(JwtClaims.forMagicLink(USER, List.of("u")).method())
        .isEqualTo(AuthMethod.MAGIC_LINK);
    assertThat(JwtClaims.forRefresh(USER, "web", List.of("u")).method())
        .isEqualTo(AuthMethod.REFRESH);

    assertThat(JwtClaims.forPasskey(USER, new byte[] {9}, "web", List.of("u")).audience())
        .isEqualTo("web");
    assertThat(JwtClaims.forBackupCode(USER, "cli", List.of("u")).audience()).isEqualTo("cli");
    assertThat(JwtClaims.forMagicLink(USER, "cli", List.of("u")).audience()).isEqualTo("cli");
  }

  @Test
  void fiveArgConstructorDefaultsAudienceToNull() {
    JwtClaims claims = new JwtClaims(USER, AuthMethod.BACKUP_CODE, null, List.of("u"), null);
    assertThat(claims.audience()).isNull();
  }

  @Test
  void rejectsBlankAudience() {
    assertThatThrownBy(
            () -> new JwtClaims(USER, AuthMethod.BACKUP_CODE, null, List.of("u"), null, "  "))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("audience");
  }

  @Test
  void rejectsNullRequiredFields() {
    assertThatThrownBy(() -> new JwtClaims(null, AuthMethod.BACKUP_CODE, null, List.of(), null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new JwtClaims(USER, null, null, List.of(), null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new JwtClaims(USER, AuthMethod.BACKUP_CODE, null, null, null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void credentialIdAccessorAndStoredCopyAreDefensive() {
    byte[] cred = {4, 5, 6};
    JwtClaims claims = JwtClaims.forPasskey(USER, cred, List.of("u"));
    cred[0] = 0; // mutate source after construction
    assertThat(claims.credentialId()).containsExactly(4, 5, 6);
    byte[] out = claims.credentialId();
    out[0] = 0; // mutate the returned array
    assertThat(claims.credentialId()).containsExactly(4, 5, 6);
  }

  @Test
  void nonPasskeyCredentialIdAccessorReturnsNull() {
    assertThat(JwtClaims.forBackupCode(USER, List.of("u")).credentialId()).isNull();
  }

  @Test
  void additionalClaimsAreCopiedDefensively() {
    Map<String, Object> extra = new HashMap<>();
    extra.put("tenant", "acme");
    JwtClaims claims =
        new JwtClaims(USER, AuthMethod.BACKUP_CODE, null, List.of("u"), extra, "web");
    extra.put("tenant", "tampered");
    assertThat(claims.additionalClaims()).containsEntry("tenant", "acme");
  }

  @Test
  void equalsAndHashCodeReflectEveryField() {
    JwtClaims a = JwtClaims.forPasskey(USER, new byte[] {1}, "web", List.of("u"));
    JwtClaims b = JwtClaims.forPasskey(USER, new byte[] {1}, "web", List.of("u"));
    assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    assertThat(a).isNotEqualTo(null).isNotEqualTo("nope");

    // Differ by credentialId content (Arrays.equals path).
    assertThat(a).isNotEqualTo(JwtClaims.forPasskey(USER, new byte[] {2}, "web", List.of("u")));
    // Differ by method.
    assertThat(JwtClaims.forBackupCode(USER, "web", List.of("u")))
        .isNotEqualTo(JwtClaims.forMagicLink(USER, "web", List.of("u")));
    // Differ by audience.
    assertThat(JwtClaims.forBackupCode(USER, "web", List.of("u")))
        .isNotEqualTo(JwtClaims.forBackupCode(USER, "cli", List.of("u")));
    // Differ by amr.
    assertThat(JwtClaims.forBackupCode(USER, "web", List.of("u")))
        .isNotEqualTo(JwtClaims.forBackupCode(USER, "web", List.of("v")));
  }

  @Test
  void toStringHexEncodesCredentialIdAndRedactsNothingSensitive() {
    String withCred =
        JwtClaims.forPasskey(USER, new byte[] {(byte) 0xAB, 0x01}, List.of("u")).toString();
    assertThat(withCred).contains("method=PASSKEY").contains("credentialId=ab01");

    String withoutCred = JwtClaims.forBackupCode(USER, List.of("u")).toString();
    assertThat(withoutCred).contains("credentialId=null");
  }
}
