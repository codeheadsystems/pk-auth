// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

/**
 * Single-table key prefixes for the pk-auth DynamoDB schema. Every partition/sort key in the table
 * is a {@code <PREFIX><id>} string; centralizing the prefixes here is what stops a writer and a
 * reader from silently disagreeing on a prefix — a mismatch would not throw, it would just fail to
 * find the row. Each constant includes its trailing {@code '#'} separator.
 *
 * <p>Package-private: these are an internal detail of the DynamoDB adapter, not part of any public
 * contract.
 */
final class DynamoKeys {

  /** User partition prefix (also the GSI hash for user-owned items). */
  static final String USER = "USER#";

  /** Username lookup prefix. */
  static final String USERNAME = "USERNAME#";

  /** Credential item prefix. */
  static final String CRED = "CRED#";

  /** Access-token (JTI) item prefix. */
  static final String AT = "AT#";

  /** One-time-passcode item prefix. */
  static final String OTP = "OTP#";

  /** Backup-code item prefix. */
  static final String BACKUP = "BACKUP#";

  /** Ceremony-challenge item prefix. */
  static final String CHAL = "CHAL#";

  /** Refresh-token item prefix (primary item and jti-index sort key). */
  static final String RT = "RT#";

  /** Refresh-token family prefix. */
  static final String RTF = "RTF#";

  private DynamoKeys() {}
}
