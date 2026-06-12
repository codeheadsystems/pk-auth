// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.jspecify.annotations.Nullable;

/**
 * Host-app input for starting an authentication ceremony. A null {@code username} allows
 * usernameless / discoverable-credential flows.
 *
 * @since 0.9.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record StartAuthenticationRequest(
    @Nullable String username, @Nullable UserVerificationRequirement userVerification) {}
