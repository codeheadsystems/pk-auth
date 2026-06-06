# 8. DynamoDB single-table design for auth items, separate users table

Date: 2026-05-14

## Status

Accepted.

## Context

The brief (§6.7, §6.7.1) calls for a single physical DynamoDB table holding every pk-auth entity (credentials, challenges, backup codes, OTP codes) plus a separate `PkAuthUsers` table for the host-app's user data. This ADR captures the why and pins down the key shapes.

## Decision

### Two tables

| Table | Purpose | Why separate? |
|---|---|---|
| `PkAuthCore` | Credentials, challenges, and (Phase 6) backup codes + OTP codes. | These are all pk-auth-owned entities; co-locating them in one table cuts the per-request control-plane overhead and supports cross-entity access patterns at a single user handle. |
| `PkAuthUsers` | Username ↔ user-handle lookup with the host-app's user attributes. | Users are host-app data (brief §6.6, §6.7). Keeping the table separate lets host apps swap in their own user store without touching the single-table; their `UserLookup` implementation simply targets a different table. |

### Key shapes

| Item | `pk` | `sk` | GSI1 (`gsi1-credential-by-id`) | Notes |
|---|---|---|---|---|
| Credential | `USER#{userHandleB64}` | `CRED#{credentialIdB64}` | `gsi1pk=CRED#{credentialIdB64}`, `gsi1sk=META` | One row per registered passkey. GSI1 supports the assertion-time "find credential by id" path where the user handle is not yet known. |
| Challenge | `CHAL#{challengeId}` | `META` | — | TTL attribute set so DynamoDB evicts expired challenges. `takeOnce` is `DeleteItem` with `ReturnValues=ALL_OLD` for atomic single-use. |

Phase 6 (shipped):

| Item | `pk` | `sk` |
|---|---|---|
| BackupCode | `USER#{userHandleB64}` | `BACKUP#{codeId}` |
| OtpCode | `USER#{userHandleB64}` | `OTP#{otpId}` |

These piggyback on the same table. Listing a user's backup codes is a single `Query` with `sk begins_with BACKUP#`.

### Separate `PkAuthUsers` table

| Attribute | Type | Notes |
|---|---|---|
| `pk` | `String` (HASH) | `USER#{userHandleB64}` |
| `sk` | `String` (RANGE) | `META` (room to expand later) |
| `gsi1pk` | `String` (GSI HASH) | `USERNAME#{usernameLowercase}` — case-folded so username lookups are predictable. |
| `gsi1sk` | `String` (GSI RANGE) | `META` |
| `userHandle` | `String` | Same value as `pk` minus the `USER#` prefix. |
| `username` | `String` | Host-app login identifier. |
| `displayName` | `String` | |
| `emailVerified` | `Boolean` | |
| `phoneVerified` | `Boolean` | |

### Binary fields encoded as base64url strings

Per brief §6.7, every binary field (challenge bytes, credential id, COSE public key) is stored as a **base64url string** rather than a binary attribute. Reasoning:

- Console inspection: operators can read item values in the DynamoDB console without manual base64 decoding.
- Cross-language: the same wire encoding is used on every code path (JSON in / JSON out, JWT subject, the JS SDK).
- Migration friendliness: future schema changes won't have to translate between B and S attribute types.

The minor size overhead (~33%) is acceptable for pk-auth's data sizes — credential public keys are ~80 bytes, and a single challenge is 32 bytes.

## Consequences

- **Positive — cheap user-scoped queries.** Listing a user's credentials, backup codes, or OTP codes is a single `Query` on the same partition.
- **Positive — host-app independence.** A host app that already runs DynamoDB can point `DynamoDbUserLookup` at its own existing users table by reusing the `UserItem` schema (or implementing `UserLookup` against an entirely different schema).
- **Positive — schema simplicity.** Four attribute definitions for the core table (`pk`, `sk`, `gsi1pk`, `gsi1sk`); no migrations were required when Phase 6 item types were added.
- **Negative — hot-partition risk on a single user with thousands of credentials.** Not a realistic scenario for consumer passkeys, but worth flagging.
- **Negative — GSI projection.** `gsi1-credential-by-id` projects ALL attributes; that's twice the storage cost on credential rows. We accept it because the assertion path needs the full credential to verify, and avoiding a second `GetItem` per assertion is the right trade for the latency floor.

## Open follow-ups

- Phase 6 (shipped): consume paths address rows by exact `(pk, sk)`; no GSI was needed.
- A future ADR may revisit GSI projection if storage cost becomes a concern.
