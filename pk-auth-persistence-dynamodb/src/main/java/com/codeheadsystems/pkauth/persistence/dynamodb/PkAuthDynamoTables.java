// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import java.util.Objects;

/**
 * Holds the names of the two physical DynamoDB tables pk-auth uses. The {@code core} table carries
 * credentials, challenges, backup codes, and OTP records; the {@code users} table carries the
 * host-app user records the {@code UserLookup} SPI reads from.
 *
 * @param core single-table for credentials, challenges, etc. (see ADR 0008)
 * @param users the {@code PkAuthUsers} table; separate per brief §6.7 because users are host-app
 *     data
 */
public record PkAuthDynamoTables(String core, String users) {

  /** Default table names matching the brief's schema. */
  public static final PkAuthDynamoTables DEFAULT =
      new PkAuthDynamoTables("PkAuthCore", "PkAuthUsers");

  /** Name of the GSI on the core table for credential-id → row lookups. */
  public static final String GSI1_CREDENTIAL_BY_ID = "gsi1-credential-by-id";

  /** Name of the GSI on the users table for username → row lookups. */
  public static final String GSI1_USER_BY_USERNAME = "gsi1-user-by-username";

  public PkAuthDynamoTables {
    Objects.requireNonNull(core, "core");
    Objects.requireNonNull(users, "users");
  }
}
