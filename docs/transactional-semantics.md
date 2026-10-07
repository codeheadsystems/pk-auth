# pk-auth Transactional Semantics

## Overview

pk-auth does not require host SPI implementations to share a transactional context. Each SPI method
is called independently, and pk-auth makes no assumptions about whether two SPI calls happen inside
a shared database transaction.

This allows hosts to mix heterogeneous backends (for example DynamoDB for `ChallengeStore` and
Postgres for `CredentialRepository`) without a distributed transaction coordinator.

## Ceremony-finish ordering

At the end of a WebAuthn registration or authentication ceremony, pk-auth calls the SPIs in this
order:

1. `ChallengeStore.takeOnce(challengeId)`: the challenge is atomically consumed and can never be
   replayed, regardless of what happens next.
2. Signature and assertion verification (in-memory, no SPI).
3. `CredentialRepository.save(credential)`: the new or updated credential is persisted.

If step 3 fails (for example a transient database error), the challenge from step 1 is already
consumed. The ceremony cannot be retried with the same challenge. The user restarts the ceremony
from the beginning, which causes pk-auth to issue a fresh challenge.

## Restart cost

Challenges are short-lived (default TTL: 5 minutes). A forced restart is a minor inconvenience in
the rare case of a transient failure, and it avoids significant complexity:

- No `TransactionTemplate` SPI hook is needed.
- Heterogeneous backends (Dynamo, Postgres, and Redis) can be mixed freely.
- The worst-case outcome of a failed save is that the user retries registration or authentication.
  An invalid credential is never accepted.

## Stronger guarantees for hosts

Hosts that need atomicity across `ChallengeStore` and `CredentialRepository` can implement both SPIs
against the same backing store and wrap their calls in a shared transaction. For example, a
Postgres-only deployment can implement both SPIs using JDBI and rely on a single database
transaction.

pk-auth does not provide a `TransactionTemplate` SPI hook today. A deployment that requires
cross-SPI atomicity must have both SPIs target the same transactional resource.

## Other SPI pairs

The same non-transactional property applies wherever pk-auth calls multiple SPIs in sequence:

| Sequence | Failure scenario | Recovery |
|---|---|---|
| `ChallengeStore.takeOnce` → `CredentialRepository.save` | Save fails; challenge is consumed. | User restarts ceremony (new challenge issued). |
| `BackupCodeRepository.consume` → JWT mint | Mint fails (for example a missing secret). | Code is consumed; user contacts support or regenerates codes. |
| `OtpRepository.consume` → phone-verified flag write | Flag write fails. | OTP is consumed; user requests a new OTP and re-verifies. |

In every case, the "consume once" side of the operation succeeds before the downstream write, and a
failure leaves the user in a recoverable (if inconvenient) state.

## Atomicity inside a single SPI call

The general "no shared transaction across SPI calls" stance does not extend to operations that
pk-auth declares atomic inside a single SPI call. Three surfaces require the implementation to
commit a multi-step change atomically. The parity-test suite exercises this on every shipped
backend: directly under concurrency for `takeOnce` and `rotateAtomically` (multi-thread and
`CountDownLatch` races), and via round-trip parity tests for the backup-code and OTP `consume`
paths.

| SPI method | Atomicity contract |
|---|---|
| `ChallengeStore.takeOnce(challengeId)` | Read + delete (or read + mark consumed) commit as one step. A second concurrent caller for the same challenge must receive `Optional.empty()`. |
| `BackupCodeRepository.consume` / `OtpRepository.consume` | The id-keyed mark-used commits as one atomic step, so exactly one of N concurrent callers wins. (The Argon2 / HMAC hash compare runs earlier in the service layer and can race; the `consume` return value is the single source of truth for which caller won.) |
| `RefreshTokenRepository.rotateAtomically` (1.1.0) | Mark the parent refresh row used and insert the successor row in a single atomic operation: a JDBI transaction, DynamoDB `TransactWriteItems`, or in-memory `ConcurrentHashMap.compute`. A non-atomic implementation has a window where a concurrent rotator's family-scorch can miss the freshly inserted successor. The contract forbids this, and the `concurrentRotationExactlyOneSucceedsFamilyRevoked` parity test (8 threads and `CountDownLatch`) enforces it against in-memory, real Postgres, and DynamoDB Local. See [ADR 0013](./adr/0013-refresh-tokens-family-rotation.md). |

Cross-SPI atomicity is not required. The `UserDeletionService` fan-out, for example, runs each
registered listener independently with best-effort, idempotent semantics and reports per-listener
success or failure through `UserDeletionResult`.
