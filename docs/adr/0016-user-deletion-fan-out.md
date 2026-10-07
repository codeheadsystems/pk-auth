# 16. User deletion fan-out is sequential and best-effort

Date: 2026-05-16

## Status

Accepted.

## Context

Through 1.0, pk-auth had no first-class user-deletion primitive. Hosts manually called
`CredentialRepository.delete(...)`, `BackupCodeRepository.deleteByUserHandle(...)`, and so on once
per credential category. With the 1.1 addition of `AccessTokenStore` (ADR 0015) and the forthcoming
refresh-token service (PR 3), the number of categories grows and a single one-call abstraction
starts to matter.

Motif's `OwnerLifecycleService` is the existence proof: a single `revokeAll(ownerId)` call iterates
every registered `AuthMethodRevocationListener` inside a single JDBI transaction with a shared
`Handle`, so listeners run atomically. Either every credential category is wiped or none is.

pk-auth cannot adopt the same model verbatim. Persistence in pk-auth spans three substrates:

- JDBI (Postgres connection pool and `Handle` transactions).
- DynamoDB (AWS SDK enhanced client; no transactional `Handle` analogue beyond `TransactWriteItems`,
  which is scoped to a single table at a time).
- In-memory testkit collections.

There is no shared transactional substrate across these. A motif-style "one Handle, one
transaction" model is structurally impossible without forcing every persistence backend into a
single shape, which would preclude the DynamoDB and in-memory backends.

Two options remained:

1. Require every listener to participate in a coordinator-driven 2PC protocol so partial failures
   roll back across substrates.
2. Run listeners sequentially, each in its own scope, tolerating partial failure and logging and
   reporting it.

Option 1 is correct but expensive, both to design and to operate. Real 2PC across JDBC and DynamoDB
requires a transaction manager (XA) that DynamoDB does not natively support, so pk-auth would have
to invent one.

Option 2 is correct enough for the use case. User deletion is an admin operation, not a hot path.
The expected operator response to a partial failure is "look at the structured log, retry the
deletion." The retry is safe because `UserDeletionListener` implementations are required to be
idempotent (deleting a user with no rows is a no-op that returns zero).

The trade-off is observable: a partial deletion leaves the user with some credential categories
intact, which is a security-relevant state if not remediated. Two mitigations apply:

1. Every listener invocation emits a structured `pkauth.user.deletion` log event with
   `outcome=ok|failed` and the failing exception. Operators monitor the log stream.
2. `UserDeletionService.deleteUser(handle)` returns a `UserDeletionResult` record with
   succeeded/failed counts and a list of failed listener names, so callers (admin endpoints,
   scripts) can programmatically detect partial failure and trigger their own retry or paging logic.

## Decision

Introduce `UserDeletionService` and `UserDeletionListener` in `pk-auth-core`
(`com.codeheadsystems.pkauth.lifecycle`). The service runs listeners in the iteration order of the
supplied collection, catches `RuntimeException` per listener, logs a structured event, and returns a
`UserDeletionResult`.

Default listener bindings shipped by the library:

- `CredentialRepositoryDeletionListener` calls `CredentialRepository.deleteByUserHandle(...)`. The
  method was added to the SPI in 1.1.0 (a breaking change; all implementations were updated; see
  `CHANGELOG.md`).
- `BackupCodeRepositoryDeletionListener` uses the existing
  `BackupCodeRepository.deleteByUserHandle(...)`.
- `OtpRepositoryDeletionListener` uses the new `OtpRepository.deleteByUserHandle(...)` method (also
  a breaking SPI addition in 1.1.0).
- `AccessTokenStoreDeletionListener` uses `AccessTokenStore.deleteAllForUser(...)`. It is harmless
  in stateless mode (the noop store returns zero).

Adapter wiring collects every `UserDeletionListener` bean into a single service:

- Spring Boot starter: a `@Bean` for each library listener, plus a `UserDeletionService` bean that
  takes `List<UserDeletionListener>`, which Spring auto-populates.
- Dropwizard bundle: Dagger `@IntoSet` multibindings. `PkAuthModule` contributes the credential and
  access-token listeners, and `AltFlowsModule` contributes the backup-code and OTP listeners. The
  slim component (no alt-flows) gets two listeners, and the full component gets four.
- Micronaut adapter: `@Singleton UserDeletionListener` factory methods, plus a
  `UserDeletionService` bean injecting `Collection<UserDeletionListener>`.

Hosts add their own listeners by declaring their own bean in the adapter's DI framework, and the
service picks them up via the same collection.

## Consequences

- Pro: one-call user deletion across every credential category the library manages. Hosts replace
  ad-hoc cleanup with `userDeletionService.deleteUser(handle)`.
- Pro: new library features (refresh tokens in PR 3) integrate automatically by adding their own
  `UserDeletionListener` to the same collection. No central registry needs updating.
- Pro: adopter-supplied listeners participate as first-class members. A host with its own user-keyed
  table (avatar storage, app-specific session data) wires a listener, and the service calls it
  alongside the library's.
- Con: the operation is not atomic. A partial deletion leaves some credential categories intact.
  Operators must monitor the structured log and retry. The alternative rejected in Context is XA
  across JDBC and DynamoDB.
- Con: the structured log is the audit trail. If operators do not consume the
  `pkauth.user.deletion` event stream, failed deletions go unnoticed until a user complains.
- Con: adding `deleteByUserHandle` to the `CredentialRepository` and `OtpRepository` SPIs is
  breaking for downstream implementations. The 1.1.0 release note calls this out, and every shipped
  pk-auth persistence module is updated as part of the same release.

## Open follow-ups

- An admin endpoint surfacing `userDeletionService.deleteUser(handle)` would let hosts trigger
  fan-out from a REST call. It is not in 1.1.0 scope.
- A retry helper that takes a `UserDeletionResult.failedListenerNames` list and re-runs just those
  listeners would simplify the operator retry flow. It is deferred until a real consumer asks for
  it.
- If a future persistence backend joins (for example a single transactional store covering every
  SPI), the service could opportunistically detect it and switch to a single-transaction fan-out.
  This is out of scope until that backend exists.
