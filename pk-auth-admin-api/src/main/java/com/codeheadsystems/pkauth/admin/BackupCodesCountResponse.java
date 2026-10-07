// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

/**
 * Wire-shape response for {@code GET /auth/admin/backup-codes/count}: JSON {@code {"remaining":
 * n}}. Promoted out of the per-adapter controllers so every adapter emits the identical envelope;
 * before promotion the Spring adapter wrapped this in {@code Map.of(...)} while Dropwizard and
 * Micronaut returned the bare integer, which made the count endpoint the only admin endpoint whose
 * shape differed across adapters.
 *
 * @param remaining number of unconsumed backup codes for the user
 * @since 0.9.1
 */
public record BackupCodesCountResponse(int remaining) {}
