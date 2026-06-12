// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.json.Base64Url;
import java.util.LinkedHashMap;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Canonical wire contract for the four ceremony endpoints. Every adapter ({@code
 * pk-auth-spring-boot-starter}, {@code pk-auth-dropwizard}, {@code pk-auth-micronaut}) routes its
 * {@link RegistrationResult} / {@link AssertionResult} through this mapper so the resulting JSON
 * body and HTTP status code are byte-identical across adapters. That's what lets the {@code
 * @pk-auth/passkeys-browser} TypeScript SDK target one wire shape and Just Work everywhere.
 *
 * <p>Body shape: every non-success carries {@code {"outcome": "<snake_case_code>", ...}}. Success
 * carries {@code {"outcome": "success", ...}} plus result-specific fields.
 *
 * <p>Status codes follow the most-explicit Spring adapter's prior behaviour (kept for backward
 * compat with the existing TS SDK and Spring integration tests):
 *
 * <ul>
 *   <li>Registration success → 200; all registration errors → 400, except {@code
 *       DuplicateCredential} → 409 and {@code RateLimited} → 429.
 *   <li>Assertion success → 200; {@code UnknownCredential} → 404; {@code CounterRegression} →
 *       409; {@code UserVerificationRequired} / {@code InvalidSignature} → 401; {@code
 *       RateLimited} → 429; the rest → 400.
 *   <li>Start ceremony rate-limit refusal (the {@code RateLimited} variant of {@code
 *       StartRegistrationResult} / {@code StartAuthenticationResult}) → 429; adapters call {@link
 *       #rateLimited()} to shape the response.
 * </ul>
 *
 * @since 0.9.0
 */
public final class CeremonyWireMapper {

  private CeremonyWireMapper() {}

  /** Carries a wire-format response: HTTP status code + a JSON-serializable body. */
  public record CeremonyResponse(int status, Map<String, Object> body) {
    public CeremonyResponse {
      body = Map.copyOf(body);
    }
  }

  /** Maps a {@link RegistrationResult} (any variant) to the canonical response shape. */
  public static CeremonyResponse forRegistration(RegistrationResult result) {
    return switch (result) {
      case RegistrationResult.Success s -> new CeremonyResponse(200, successBody(s.credential()));
      case RegistrationResult.InvalidChallenge ic ->
          new CeremonyResponse(400, errorBody("invalid_challenge", "detail", ic.detail()));
      case RegistrationResult.OriginMismatch om ->
          new CeremonyResponse(
              400,
              ordered(
                  "outcome", "origin_mismatch",
                  "expected", om.expected(),
                  "actual", om.actual()));
      case RegistrationResult.AttestationRejected ar ->
          new CeremonyResponse(400, errorBody("attestation_rejected", "reason", ar.reason()));
      case RegistrationResult.DuplicateCredential dc ->
          new CeremonyResponse(
              409,
              errorBody(
                  "duplicate_credential",
                  "credentialId",
                  Base64Url.encode(dc.credentialId().value())));
      case RegistrationResult.InvalidPayload ip ->
          new CeremonyResponse(400, errorBody("invalid_payload", "detail", ip.detail()));
      case RegistrationResult.RateLimited rl ->
          new CeremonyResponse(429, Map.of("outcome", "rate_limited"));
    };
  }

  /**
   * Canonical 429 response shape for {@code start*} ceremony rate-limit refusals. Adapter
   * controllers use this for the {@code RateLimited} variant of {@code StartRegistrationResult} /
   * {@code StartAuthenticationResult}.
   *
   * @return canonical rate-limited response (HTTP 429, body {@code {"outcome": "rate_limited"}})
   * @since 0.9.1
   */
  public static CeremonyResponse rateLimited() {
    return new CeremonyResponse(429, Map.of("outcome", "rate_limited"));
  }

  /**
   * Maps a successful {@link AssertionResult.Success} to the canonical assertion-success body. The
   * caller supplies the freshly-minted JWT and the credential label (looked up from the host's
   * repository) so this method can stay free of host-specific lookups.
   */
  public static CeremonyResponse forAssertionSuccess(
      AssertionResult.Success success, String token, @Nullable String label) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("outcome", "success");
    body.put("userHandle", Base64Url.encode(success.userHandle().value()));
    body.put("credentialId", success.credentialId().b64url());
    if (label != null) {
      body.put("label", label);
    }
    body.put("token", token);
    body.put("signCount", success.signCount());
    return new CeremonyResponse(200, body);
  }

  /** Maps a non-success {@link AssertionResult} to the canonical error body + HTTP status. */
  public static CeremonyResponse forAssertionError(AssertionResult result) {
    return switch (result) {
      case AssertionResult.Success ignored ->
          throw new IllegalArgumentException(
              "forAssertionError called with Success; use forAssertionSuccess instead");
      case AssertionResult.UnknownCredential uc ->
          new CeremonyResponse(
              404,
              errorBody(
                  "unknown_credential",
                  "credentialId",
                  Base64Url.encode(uc.credentialId().value())));
      case AssertionResult.InvalidChallenge ic ->
          new CeremonyResponse(400, errorBody("invalid_challenge", "detail", ic.detail()));
      case AssertionResult.OriginMismatch om ->
          new CeremonyResponse(
              400,
              ordered(
                  "outcome", "origin_mismatch",
                  "expected", om.expected(),
                  "actual", om.actual()));
      case AssertionResult.CounterRegression cr ->
          new CeremonyResponse(
              409,
              ordered(
                  "outcome", "counter_regression",
                  "stored", cr.stored(),
                  "received", cr.received()));
      case AssertionResult.UserVerificationRequired uvr ->
          new CeremonyResponse(401, Map.of("outcome", "user_verification_required"));
      case AssertionResult.InvalidSignature is ->
          new CeremonyResponse(401, Map.of("outcome", "invalid_signature"));
      case AssertionResult.RateLimited rl ->
          new CeremonyResponse(429, Map.of("outcome", "rate_limited"));
    };
  }

  private static Map<String, Object> successBody(CredentialRecord credential) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("outcome", "success");
    body.put("userHandle", Base64Url.encode(credential.userHandle().value()));
    body.put("credentialId", credential.credentialId().b64url());
    body.put("label", credential.label());
    return body;
  }

  private static Map<String, Object> errorBody(String outcome, String key, Object value) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("outcome", outcome);
    body.put(key, value);
    return body;
  }

  /**
   * Type-erased small ordered-map helper. Equivalent to {@code Map.of} but preserves insertion
   * order.
   */
  private static Map<String, Object> ordered(Object... kv) {
    Map<String, Object> body = new LinkedHashMap<>();
    for (int i = 0; i < kv.length; i += 2) {
      body.put((String) kv[i], kv[i + 1]);
    }
    return body;
  }
}
