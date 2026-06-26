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

  /**
   * {@code Retry-After} hint (seconds) emitted on every ceremony 429, mirroring the {@code
   * Retry-After} the admin endpoints already send on their rate-limit refusals. The value is a
   * conservative constant matching {@code InMemoryCeremonyRateLimiter.DEFAULT_WINDOW} (1 minute):
   * the {@link com.codeheadsystems.pkauth.spi.CeremonyRateLimiter} SPI is boolean-only and exposes
   * no per-call window, so an exact remaining-time cannot be computed here. A host that tightens or
   * widens its limiter window may therefore serve a slightly stale hint, which {@code Retry-After}
   * explicitly permits (it is advisory). Hosts wanting an exact value can override the header.
   */
  private static final Map<String, String> RATE_LIMIT_HEADERS = Map.of("Retry-After", "60");

  /**
   * Canonical 429 ceremony refusal: {@code {"outcome":"rate_limited"}} body + {@code Retry-After}.
   */
  private static CeremonyResponse rateLimitedResponse() {
    return new CeremonyResponse(429, Map.of("outcome", "rate_limited"), RATE_LIMIT_HEADERS);
  }

  /**
   * Carries a wire-format response: HTTP status code, a JSON-serializable body, and response
   * headers. Adapters MUST copy {@link #headers()} onto the native HTTP response (e.g. {@code
   * Retry-After} on a 429); a body-only adapter silently drops them.
   *
   * <p>The {@code headers} component was added in 2.1.0; the two-arg constructor preserves the
   * prior {@code (status, body)} call sites with no headers.
   *
   * @param status the HTTP status code
   * @param body the JSON-serializable response body
   * @param headers response headers to copy onto the native HTTP response (since 2.1.0)
   */
  public record CeremonyResponse(
      int status, Map<String, Object> body, Map<String, String> headers) {
    public CeremonyResponse {
      body = Map.copyOf(body);
      headers = Map.copyOf(headers);
    }

    /**
     * Convenience constructor for a response with no extra headers.
     *
     * @param status the HTTP status code
     * @param body the JSON-serializable response body
     */
    public CeremonyResponse(int status, Map<String, Object> body) {
      this(status, body, Map.of());
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
      case RegistrationResult.RateLimited rl -> rateLimitedResponse();
    };
  }

  /**
   * Canonical 429 response shape for {@code start*} ceremony rate-limit refusals. Adapter
   * controllers use this for the {@code RateLimited} variant of {@code StartRegistrationResult} /
   * {@code StartAuthenticationResult}.
   *
   * @return canonical rate-limited response (HTTP 429, body {@code {"outcome": "rate_limited"}},
   *     plus a {@code Retry-After} header since 2.1.0)
   * @since 0.9.1
   */
  public static CeremonyResponse rateLimited() {
    return rateLimitedResponse();
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
      case AssertionResult.RateLimited rl -> rateLimitedResponse();
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
