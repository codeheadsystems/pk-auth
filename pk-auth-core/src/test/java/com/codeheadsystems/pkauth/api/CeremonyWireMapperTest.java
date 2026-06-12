// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.CeremonyWireMapper.CeremonyResponse;
import com.codeheadsystems.pkauth.credential.AuthenticatorData;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.json.Base64Url;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Locks in the wire contract that every adapter ({@code pk-auth-spring-boot-starter}, {@code
 * pk-auth-dropwizard}, {@code pk-auth-micronaut}) is required to emit. Failures here mean adapters
 * may diverge from the canonical TS-SDK-targeted shape.
 */
class CeremonyWireMapperTest {

  private static final UserHandle USER = UserHandle.of(new byte[] {1, 2, 3, 4});
  private static final byte[] CRED_ID = new byte[] {9, 9, 9, 9};
  private static final CredentialId CRED_ID_VALUE = CredentialId.of(CRED_ID);
  private static final String CRED_ID_B64URL = Base64Url.encode(CRED_ID);

  @Test
  void registrationSuccessShape() {
    CredentialRecord cred =
        new CredentialRecord(
            CRED_ID_VALUE,
            USER,
            new byte[] {1, 2},
            0L,
            "Test Key",
            null,
            Set.of(),
            false,
            false,
            Instant.parse("2026-05-14T12:00:00Z"),
            null);
    AuthenticatorData authData =
        new AuthenticatorData(new byte[] {0}, true, true, false, false, true, false, 0L);
    CeremonyResponse r =
        CeremonyWireMapper.forRegistration(new RegistrationResult.Success(cred, authData));
    assertThat(r.status()).isEqualTo(200);
    assertThat(r.body())
        .containsEntry("outcome", "success")
        .containsEntry("userHandle", Base64Url.encode(USER.value()))
        .containsEntry("credentialId", Base64Url.encode(CRED_ID))
        .containsEntry("label", "Test Key");
  }

  @Test
  void registrationDuplicateIs409WithCredentialIdEcho() {
    CeremonyResponse r =
        CeremonyWireMapper.forRegistration(
            new RegistrationResult.DuplicateCredential(CRED_ID_VALUE));
    assertThat(r.status()).isEqualTo(409);
    assertThat(r.body())
        .containsEntry("outcome", "duplicate_credential")
        .containsEntry("credentialId", CRED_ID_B64URL);
  }

  @Test
  void registrationInvalidChallengeIs400() {
    CeremonyResponse r =
        CeremonyWireMapper.forRegistration(new RegistrationResult.InvalidChallenge("expired"));
    assertThat(r.status()).isEqualTo(400);
    assertThat(r.body())
        .containsEntry("outcome", "invalid_challenge")
        .containsEntry("detail", "expired");
  }

  @Test
  void registrationOriginMismatchIs400WithExpectedAndActual() {
    CeremonyResponse r =
        CeremonyWireMapper.forRegistration(
            new RegistrationResult.OriginMismatch("https://expected", "https://attacker"));
    assertThat(r.status()).isEqualTo(400);
    assertThat(r.body())
        .containsEntry("outcome", "origin_mismatch")
        .containsEntry("expected", "https://expected")
        .containsEntry("actual", "https://attacker");
  }

  @Test
  void registrationAttestationRejectedIs400WithReason() {
    CeremonyResponse r =
        CeremonyWireMapper.forRegistration(
            new RegistrationResult.AttestationRejected("untrusted root"));
    assertThat(r.status()).isEqualTo(400);
    assertThat(r.body())
        .containsEntry("outcome", "attestation_rejected")
        .containsEntry("reason", "untrusted root");
  }

  @Test
  void registrationInvalidPayloadIs400WithDetail() {
    CeremonyResponse r =
        CeremonyWireMapper.forRegistration(new RegistrationResult.InvalidPayload("bad CBOR"));
    assertThat(r.status()).isEqualTo(400);
    assertThat(r.body())
        .containsEntry("outcome", "invalid_payload")
        .containsEntry("detail", "bad CBOR");
  }

  @Test
  void registrationRateLimitedIs429() {
    CeremonyResponse r =
        CeremonyWireMapper.forRegistration(new RegistrationResult.RateLimited("register"));
    assertThat(r.status()).isEqualTo(429);
    assertThat(r.body()).containsEntry("outcome", "rate_limited");
  }

  @Test
  void assertionSuccessIncludesToken() {
    AssertionResult.Success success =
        new AssertionResult.Success(USER, CRED_ID_VALUE, 42L, AssertionResult.CounterStatus.OK);
    CeremonyResponse r = CeremonyWireMapper.forAssertionSuccess(success, "the.jwt.token", "Phone");
    assertThat(r.status()).isEqualTo(200);
    assertThat(r.body())
        .containsEntry("outcome", "success")
        .containsEntry("userHandle", Base64Url.encode(USER.value()))
        .containsEntry("credentialId", CRED_ID_B64URL)
        .containsEntry("label", "Phone")
        .containsEntry("token", "the.jwt.token")
        .containsEntry("signCount", 42L);
  }

  @Test
  void assertionSuccessOmitsLabelWhenAbsent() {
    AssertionResult.Success success =
        new AssertionResult.Success(USER, CRED_ID_VALUE, 1L, AssertionResult.CounterStatus.OK);
    CeremonyResponse r = CeremonyWireMapper.forAssertionSuccess(success, "tok", null);
    assertThat(r.body()).doesNotContainKey("label").containsEntry("token", "tok");
  }

  @Test
  void assertionUnknownCredentialIs404() {
    CeremonyResponse r =
        CeremonyWireMapper.forAssertionError(new AssertionResult.UnknownCredential(CRED_ID_VALUE));
    assertThat(r.status()).isEqualTo(404);
    assertThat(r.body())
        .containsEntry("outcome", "unknown_credential")
        .containsEntry("credentialId", CRED_ID_B64URL);
  }

  @Test
  void assertionCounterRegressionIs409WithStoredAndReceived() {
    CeremonyResponse r =
        CeremonyWireMapper.forAssertionError(new AssertionResult.CounterRegression(10L, 5L));
    assertThat(r.status()).isEqualTo(409);
    assertThat(r.body())
        .containsEntry("outcome", "counter_regression")
        .containsEntry("stored", 10L)
        .containsEntry("received", 5L);
  }

  @Test
  void assertionInvalidChallengeIs400WithDetail() {
    CeremonyResponse r =
        CeremonyWireMapper.forAssertionError(new AssertionResult.InvalidChallenge("expired"));
    assertThat(r.status()).isEqualTo(400);
    assertThat(r.body())
        .containsEntry("outcome", "invalid_challenge")
        .containsEntry("detail", "expired");
  }

  @Test
  void assertionOriginMismatchIs400WithExpectedAndActual() {
    CeremonyResponse r =
        CeremonyWireMapper.forAssertionError(
            new AssertionResult.OriginMismatch("https://expected", "https://attacker"));
    assertThat(r.status()).isEqualTo(400);
    assertThat(r.body())
        .containsEntry("outcome", "origin_mismatch")
        .containsEntry("expected", "https://expected")
        .containsEntry("actual", "https://attacker");
  }

  @Test
  void assertionRateLimitedIs429() {
    CeremonyResponse r =
        CeremonyWireMapper.forAssertionError(new AssertionResult.RateLimited("authenticate"));
    assertThat(r.status()).isEqualTo(429);
    assertThat(r.body()).containsEntry("outcome", "rate_limited");
  }

  @Test
  void startCeremonyRateLimitedIs429() {
    CeremonyResponse r = CeremonyWireMapper.rateLimited();
    assertThat(r.status()).isEqualTo(429);
    assertThat(r.body()).containsEntry("outcome", "rate_limited");
  }

  @Test
  void assertionUserVerificationRequiredIs401() {
    CeremonyResponse r =
        CeremonyWireMapper.forAssertionError(new AssertionResult.UserVerificationRequired());
    assertThat(r.status()).isEqualTo(401);
    assertThat(r.body()).containsEntry("outcome", "user_verification_required");
  }

  @Test
  void assertionInvalidSignatureIs401() {
    CeremonyResponse r =
        CeremonyWireMapper.forAssertionError(new AssertionResult.InvalidSignature());
    assertThat(r.status()).isEqualTo(401);
    assertThat(r.body()).containsEntry("outcome", "invalid_signature");
  }

  @Test
  void forAssertionErrorRejectsSuccess() {
    AssertionResult.Success success =
        new AssertionResult.Success(USER, CRED_ID_VALUE, 0L, AssertionResult.CounterStatus.OK);
    assertThatThrownBy(() -> CeremonyWireMapper.forAssertionError(success))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void responseBodyIsImmutable() {
    CeremonyResponse r =
        CeremonyWireMapper.forAssertionError(new AssertionResult.InvalidSignature());
    assertThatThrownBy(() -> r.body().put("hacked", "yes"))
        .isInstanceOf(UnsupportedOperationException.class);
  }

  /**
   * Tripwire: if a new {@link RegistrationResult} variant is added, this fails until the variant is
   * both wired in {@link CeremonyWireMapper#forRegistration} and covered by a test above. The
   * {@code switch} in the mapper is already compile-time exhaustive; this guards the *test*
   * coverage.
   */
  @Test
  void everyRegistrationVariantIsCoveredByATest() {
    assertThat(simpleNamesOfPermittedSubclasses(RegistrationResult.class))
        .containsExactlyInAnyOrder(
            "Success",
            "InvalidChallenge",
            "OriginMismatch",
            "AttestationRejected",
            "DuplicateCredential",
            "InvalidPayload",
            "RateLimited");
  }

  /**
   * Tripwire: if a new {@link AssertionResult} variant is added, this fails until the variant is
   * both wired in {@link CeremonyWireMapper#forAssertionError} (or {@code forAssertionSuccess}) and
   * covered by a test above.
   */
  @Test
  void everyAssertionVariantIsCoveredByATest() {
    assertThat(simpleNamesOfPermittedSubclasses(AssertionResult.class))
        .containsExactlyInAnyOrder(
            "Success",
            "UnknownCredential",
            "InvalidChallenge",
            "OriginMismatch",
            "CounterRegression",
            "UserVerificationRequired",
            "InvalidSignature",
            "RateLimited");
  }

  private static Set<String> simpleNamesOfPermittedSubclasses(Class<?> sealed) {
    Class<?>[] permitted = sealed.getPermittedSubclasses();
    assertThat(permitted).as("expected a sealed type").isNotNull();
    return java.util.Arrays.stream(permitted)
        .map(Class::getSimpleName)
        .collect(java.util.stream.Collectors.toSet());
  }
}
