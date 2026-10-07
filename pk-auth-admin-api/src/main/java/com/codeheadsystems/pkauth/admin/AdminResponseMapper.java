// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import org.jspecify.annotations.Nullable;

/**
 * Framework-neutral mapper from {@link AdminResult} to an HTTP response shape. Each adapter
 * (Spring, Dropwizard, Micronaut) holds a thin wrapper that converts the returned {@link
 * AdminResponse} into its native HTTP type; {@link AdminResponseMapper} owns the status codes, the
 * {@code Retry-After} header floor, and the unified error envelope shape.
 *
 * <p>Before this helper existed each adapter hand-rolled the same {@code switch} over the {@link
 * AdminResult} variants plus its own copy of {@code errorEnvelope(...)}. Brief §6.9 requires "a
 * single shared {@code AdminResultMapper}"; this is that mapper.
 *
 * <p>Status codes:
 *
 * <ul>
 *   <li>{@link AdminResult.Success} with non-null payload → 200; with {@code null} payload → 204.
 *   <li>{@link AdminResult.NotFound} → 404, body {@code {"outcome":"not_found",…}}.
 *   <li>{@link AdminResult.Forbidden} → 403, body {@code {"outcome":"forbidden",…}}.
 *   <li>{@link AdminResult.ValidationFailed} → 400, body {@code {"outcome":"validation_failed",…}}.
 *   <li>{@link AdminResult.Conflict} → 409, body {@code {"outcome":"conflict",…}}.
 *   <li>{@link AdminResult.RateLimited} → 429 with {@code Retry-After} header (floor 1 second).
 * </ul>
 *
 * @since 0.9.1
 */
public final class AdminResponseMapper {

  private AdminResponseMapper() {}

  /**
   * Adapter-neutral HTTP response carrier. {@code body} is {@code null} only for 204; {@code
   * headers} is empty for everything except 429.
   */
  public record AdminResponse(int status, @Nullable Object body, Map<String, String> headers) {
    public AdminResponse {
      Objects.requireNonNull(headers, "headers");
      headers = Map.copyOf(headers);
    }
  }

  /**
   * Builds an {@link AdminResponse} where a {@link AdminResult.Success} value is first transformed
   * via {@code successMapper} (commonly to wrap a primitive payload in a typed response record such
   * as {@code BackupCodesCountResponse}). Non-success variants behave as in {@link
   * #toResponse(AdminResult)}.
   */
  public static <T> AdminResponse toResponse(AdminResult<T> result, Function<T, ?> successMapper) {
    Objects.requireNonNull(successMapper, "successMapper");
    if (result instanceof AdminResult.Success<T> s) {
      Object mapped = successMapper.apply(s.value());
      if (mapped == null) {
        return new AdminResponse(204, null, Map.of());
      }
      return new AdminResponse(200, mapped, Map.of());
    }
    return toResponse(result);
  }

  /** Builds the canonical {@link AdminResponse} for {@code result}. */
  public static AdminResponse toResponse(AdminResult<?> result) {
    return switch (result) {
      case AdminResult.Success<?> s when s.value() == null ->
          new AdminResponse(204, null, Map.of());
      case AdminResult.Success<?> s -> new AdminResponse(200, s.value(), Map.of());
      case AdminResult.NotFound<?> n ->
          new AdminResponse(404, errorEnvelope("not_found", null), Map.of());
      case AdminResult.Forbidden<?> f ->
          new AdminResponse(403, errorEnvelope("forbidden", null), Map.of());
      case AdminResult.ValidationFailed<?> v ->
          new AdminResponse(400, errorEnvelope("validation_failed", v.detail()), Map.of());
      case AdminResult.Conflict<?> c ->
          new AdminResponse(409, errorEnvelope("conflict", c.detail()), Map.of());
      case AdminResult.RateLimited<?> r ->
          new AdminResponse(
              429,
              errorEnvelope("rate_limited", null),
              Map.of("Retry-After", Long.toString(Math.max(1, r.retryAfter().toSeconds()))));
    };
  }

  /**
   * Builds the unified error envelope: {@code {"outcome": "<code>", "error": "<code>", "detail":
   * "<message>"?}}. Both {@code outcome} and {@code error} carry the same machine-readable tag so
   * clients that key off either field keep working; {@code detail} is omitted when {@code null}.
   */
  public static Map<String, Object> errorEnvelope(String code, @Nullable String detail) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("outcome", code);
    body.put("error", code);
    if (detail != null) {
      body.put("detail", detail);
    }
    return body;
  }
}
