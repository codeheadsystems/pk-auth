// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import org.jspecify.annotations.Nullable;

/**
 * Shared wire-shape request bodies for the {@code /auth/admin/**} endpoints (brief §6.9). Promoted
 * out of the per-adapter controllers so that Spring, Dropwizard, and Micronaut accept byte-for-byte
 * identical JSON and so adapter authors cannot drift the contract by accident.
 *
 * <p>All fields are {@link Nullable} on the Java side: the adapter is responsible for translating a
 * {@code null} or absent value into the appropriate {@link AdminResult.ValidationFailed} via {@link
 * AdminService}; the request DTOs themselves never throw.
 *
 * @since 0.9.1
 */
public final class AdminRequests {

  private AdminRequests() {}

  /**
   * Body for {@code PATCH /auth/admin/credentials/{credentialId}}.
   *
   * @param label new human-readable label for the credential
   * @since 0.9.1
   */
  public record RenameCredential(@Nullable String label) {}

  /**
   * Body for {@code POST /auth/admin/email/start-verification}.
   *
   * @param email RFC-5322 address to send the verification token to
   * @since 0.9.1
   */
  public record StartEmailVerification(@Nullable String email) {}

  /**
   * Body for {@code POST /auth/admin/email/complete-verification}. Unauthenticated per brief §6.9;
   * the token identifies the user.
   *
   * @param token verification token previously dispatched to the user's inbox
   * @since 0.9.1
   */
  public record FinishEmailVerification(@Nullable String token) {}

  /**
   * Body for {@code POST /auth/admin/phone/start-verification}.
   *
   * @param phone E.164-formatted phone number to dispatch the OTP to
   * @since 0.9.1
   */
  public record StartPhoneVerification(@Nullable String phone) {}

  /**
   * Body for {@code POST /auth/admin/phone/complete-verification}.
   *
   * @param phone E.164-formatted phone number the OTP was sent to
   * @param code one-time code entered by the user
   * @since 0.9.1
   */
  public record FinishPhoneVerification(@Nullable String phone, @Nullable String code) {}
}
