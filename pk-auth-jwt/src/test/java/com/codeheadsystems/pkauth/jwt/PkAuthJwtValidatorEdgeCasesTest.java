// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

/**
 * Exercises the malformed / missing-claim / wrong-shape branches of {@link
 * PkAuthJwtValidator#validate(String)} that the happy-path round-trip tests don't reach. Each test
 * hand-builds a structurally valid, correctly signed JWT and then perturbs exactly one claim so the
 * validator's defensive branch fires.
 */
class PkAuthJwtValidatorEdgeCasesTest {

  private static final Instant NOW = Instant.parse("2026-05-13T12:00:00Z");
  private static final String ISSUER = "https://pkauth.example.com";
  private static final String AUDIENCE = "api.example.com";
  // HS256 keyset built from a fixed 32-byte secret. JwtKeyset.hs256 assigns kid="current", so the
  // raw tokens below must carry a matching kid header to pass the kid filter.
  private static final byte[] SECRET = new byte[32];
  private static final JwtKeyset KEYSET = JwtKeyset.hs256(SECRET);

  private final PkAuthJwtValidator validator =
      new PkAuthJwtValidator(JwtConfig.defaults(ISSUER, AUDIENCE), KEYSET, fixedClock(NOW));

  @Test
  void wrongAlgorithmHeaderIsInvalidSignature() {
    // A perfectly good HS256 token offered to an ES256-only validator: the alg check trips before
    // any key is tried.
    JwtKeyset es = JwtKeyset.es256(generateEcKeyset());
    PkAuthJwtIssuer issuer =
        new PkAuthJwtIssuer(JwtConfig.defaults(ISSUER, AUDIENCE), KEYSET, fixedClock(NOW));
    String hsToken =
        issuer.issue(JwtClaims.forBackupCode(UserHandle.of(new byte[] {1}), List.of("user")));
    PkAuthJwtValidator esValidator =
        new PkAuthJwtValidator(JwtConfig.defaults(ISSUER, AUDIENCE), es, fixedClock(NOW));
    assertThat(esValidator.validate(hsToken))
        .isInstanceOf(JwtVerificationResult.InvalidSignature.class);
  }

  @Test
  void missingExpClaimIsMissingClaim() {
    String token = signed(b -> b.expirationTime(null));
    assertThat(validator.validate(token))
        .isInstanceOfSatisfying(
            JwtVerificationResult.MissingClaim.class, r -> assertThat(r.name()).isEqualTo("exp"));
  }

  @Test
  void missingSubjectIsMissingClaim() {
    String token = signed(b -> b.subject(null));
    assertThat(validator.validate(token))
        .isInstanceOfSatisfying(
            JwtVerificationResult.MissingClaim.class, r -> assertThat(r.name()).isEqualTo("sub"));
  }

  @Test
  void undecodableSubjectIsMalformed() {
    // '!' is outside the base64url alphabet → Base64Url.decode throws → Malformed.
    String token = signed(b -> b.subject("!!!not-base64url!!!"));
    assertThat(validator.validate(token))
        .isInstanceOfSatisfying(
            JwtVerificationResult.Malformed.class,
            r -> assertThat(r.detail()).contains("invalid sub"));
  }

  @Test
  void missingMethodClaimIsMissingClaim() {
    String token = signed(b -> b.claim(PkAuthJwtIssuer.CLAIM_METHOD, null));
    assertThat(validator.validate(token))
        .isInstanceOfSatisfying(
            JwtVerificationResult.MissingClaim.class,
            r -> assertThat(r.name()).isEqualTo(PkAuthJwtIssuer.CLAIM_METHOD));
  }

  @Test
  void unknownMethodClaimIsMalformed() {
    String token = signed(b -> b.claim(PkAuthJwtIssuer.CLAIM_METHOD, "telepathy"));
    assertThat(validator.validate(token))
        .isInstanceOfSatisfying(
            JwtVerificationResult.Malformed.class,
            r -> assertThat(r.detail()).contains("unknown pkauth.method"));
  }

  @Test
  void passkeyMethodWithoutCredentialIsMissingClaim() {
    String token = signed(b -> b.claim(PkAuthJwtIssuer.CLAIM_METHOD, "passkey"));
    assertThat(validator.validate(token))
        .isInstanceOfSatisfying(
            JwtVerificationResult.MissingClaim.class,
            r -> assertThat(r.name()).isEqualTo(PkAuthJwtIssuer.CLAIM_CRED));
  }

  @Test
  void passkeyMethodWithUndecodableCredentialIsMalformed() {
    String token =
        signed(
            b ->
                b.claim(PkAuthJwtIssuer.CLAIM_METHOD, "passkey")
                    .claim(PkAuthJwtIssuer.CLAIM_CRED, "!!!bad!!!"));
    assertThat(validator.validate(token))
        .isInstanceOfSatisfying(
            JwtVerificationResult.Malformed.class,
            r -> assertThat(r.detail()).contains("invalid pkauth.cred"));
  }

  @Test
  void credentialOnNonPasskeyMethodIsMalformed() {
    String token =
        signed(
            b ->
                b.claim(PkAuthJwtIssuer.CLAIM_METHOD, "backup-code")
                    .claim(PkAuthJwtIssuer.CLAIM_CRED, Base64Url.encode(new byte[] {1, 2})));
    assertThat(validator.validate(token))
        .isInstanceOfSatisfying(
            JwtVerificationResult.Malformed.class,
            r -> assertThat(r.detail()).contains("pkauth.cred must not appear"));
  }

  @Test
  void passkeyTokenWithCredentialRoundTripsCredentialId() {
    byte[] credId = {7, 7, 9, 9};
    String token =
        signed(
            b ->
                b.claim(PkAuthJwtIssuer.CLAIM_METHOD, "passkey")
                    .claim(PkAuthJwtIssuer.CLAIM_CRED, Base64Url.encode(credId)));
    JwtVerificationResult result = validator.validate(token);
    assertThat(result).isInstanceOf(JwtVerificationResult.Success.class);
    JwtClaims claims = ((JwtVerificationResult.Success) result).claims();
    assertThat(claims.method()).isEqualTo(AuthMethod.PASSKEY);
    assertThat(claims.credentialId()).containsExactly(credId);
  }

  @Test
  void absentAmrClaimBecomesEmptyList() {
    String token = signed(b -> b.claim(PkAuthJwtIssuer.CLAIM_AMR, null));
    JwtVerificationResult result = validator.validate(token);
    assertThat(result).isInstanceOf(JwtVerificationResult.Success.class);
    assertThat(((JwtVerificationResult.Success) result).claims().amr()).isEmpty();
  }

  @Test
  void unknownExtraClaimsSurviveAsAdditionalClaims() {
    String token = signed(b -> b.claim("tenant", "acme").claim("plan", "pro"));
    JwtVerificationResult result = validator.validate(token);
    assertThat(result).isInstanceOf(JwtVerificationResult.Success.class);
    assertThat(((JwtVerificationResult.Success) result).claims().additionalClaims())
        .containsEntry("tenant", "acme")
        .containsEntry("plan", "pro");
  }

  @Test
  void statefulStoreRejectsTokenWithoutJtiAsMissingClaim() {
    // A stateful store (non-noop) whose exists() always returns true — so the only way to reach a
    // failure here is the jti==null guard, not a store miss.
    AccessTokenStore store =
        new AccessTokenStore() {
          @Override
          public void record(
              String jti,
              UserHandle userHandle,
              String audience,
              java.util.Optional<String> deviceId,
              Instant issuedAt,
              Instant expiresAt) {}

          @Override
          public boolean exists(String jti) {
            return true;
          }

          @Override
          public boolean delete(UserHandle userHandle, String jti) {
            return false;
          }

          @Override
          public int deleteAllForUser(UserHandle userHandle) {
            return 0;
          }

          @Override
          public int deleteExpiredBefore(Instant before) {
            return 0;
          }
        };
    PkAuthJwtValidator stateful =
        new PkAuthJwtValidator(
            JwtConfig.defaults(ISSUER, AUDIENCE),
            KEYSET,
            fixedClock(NOW),
            RevocationCheck.allow(),
            store);
    String token = signed(b -> b.jwtID(null));
    assertThat(stateful.validate(token))
        .isInstanceOfSatisfying(
            JwtVerificationResult.MissingClaim.class, r -> assertThat(r.name()).isEqualTo("jti"));
  }

  // -- helpers ------------------------------------------------------------------------------

  /**
   * Builds a fully valid backup-code JWT (kid="current", correct iss/aud/sub/exp/method/amr) then
   * applies {@code customizer} so a single test can null out or override one claim.
   */
  private static String signed(Consumer<JWTClaimsSet.Builder> customizer) {
    JWTClaimsSet.Builder builder =
        new JWTClaimsSet.Builder()
            .issuer(ISSUER)
            .audience(AUDIENCE)
            .subject(Base64Url.encode(new byte[] {1, 2, 3}))
            .issueTime(Date.from(NOW))
            .notBeforeTime(Date.from(NOW))
            .expirationTime(Date.from(NOW.plus(Duration.ofMinutes(15))))
            .jwtID(UUID.randomUUID().toString())
            .claim(PkAuthJwtIssuer.CLAIM_METHOD, "backup-code")
            .claim(PkAuthJwtIssuer.CLAIM_AMR, List.of("user"));
    customizer.accept(builder);
    try {
      JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("current").build();
      SignedJWT jwt = new SignedJWT(header, builder.build());
      jwt.sign(new MACSigner(SECRET));
      return jwt.serialize();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static com.nimbusds.jose.jwk.ECKey generateEcKeyset() {
    try {
      return new com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256)
          .keyID("ec-1")
          .generate();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static ClockProvider fixedClock(Instant instant) {
    return ClockProvider.fromClock(Clock.fixed(instant, ZoneOffset.UTC));
  }
}
