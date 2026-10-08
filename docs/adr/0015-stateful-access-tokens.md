# 15. Stateful access tokens via AccessTokenStore SPI

Date: 2026-05-16

## Status

Accepted.

## Context

Through 1.0, pk-auth issued stateless JWTs (ADR 0005) and exposed a `RevocationCheck` SPI as a
deny-list escape hatch: hosts that needed early invalidation could keep a small in-process set of
"revoked jtis" and the validator would consult it. The pattern works but does not match the way
every serious consumer ends up writing the code. Motif's `MotifJwtIssuer` demonstrates the actual
pattern in production use:

1. On every issue, persist the JTI to an `access_tokens` table.
2. On every validate, look the JTI up; if absent, reject.
3. On logout, delete the JTI.
4. On user delete, delete every JTI for that user.

The deny-list shape inverts that. A positive allow-list means "this token was issued by pk-auth and
has not been deleted", and "deleted" covers logout, admin revocation, password reset, account
compromise response, and user deletion uniformly. The cost is one row per issued token plus one read
per validation. For the deployments that need revocability at all, this cost shape is small,
predictable, and equivalent to a session table.

The 1.1.0 release adds the positive-allow primitive without removing the existing deny-list. Both
coexist:

- `RevocationCheck` is a fast, in-process deny-list. It suits hosts that issue many millions of
  tokens per day and only want to invalidate a tiny subset proactively (for example a "session
  revoked" stream from a security event bus).
- `AccessTokenStore` is a durable allow-list. It suits hosts that issue meaningfully fewer tokens
  (admin sessions, mobile clients) and want logout to take effect before the JWT's `exp`. It is the
  recommended path.

## Decision

Introduce `AccessTokenStore` in `pk-auth-jwt` with the surface:

```java
public interface AccessTokenStore {
  void record(String jti, UserHandle, String audience, Optional<String> deviceId,
              Instant issuedAt, Instant expiresAt);
  boolean exists(String jti);
  boolean delete(UserHandle userHandle, String jti);
  int deleteAllForUser(UserHandle userHandle);
  int deleteExpiredBefore(Instant before);
  static AccessTokenStore noop();
}
```

`PkAuthJwtIssuer.issue(JwtClaims)` always calls `store.record(...)` after signing and before
returning the wire token. If `record` throws, issuance fails; partial state (token returned but
unrecorded) is not tolerated.

`PkAuthJwtValidator.validate(String)` calls `store.exists(jti)` after the signature, issuer,
audience, and skew checks, alongside the existing `RevocationCheck`. A `false` return (jti not in
store) maps to `JwtVerificationResult.Revoked`, the same outcome as a deny-list hit, so consumers do
not have to learn a new sealed-result variant.

The default binding is `AccessTokenStore.noop()`: `record` discards, `exists` returns `true` for
every jti, and the delete methods return zero. This preserves stateless JWT behaviour for hosts that
do not bind a real store, so the "feature is opt-in by binding a different bean" pattern stays
clean, with no `TokenMode` enum and no two-place configuration pitfall.

Implementations ship in `pk-auth-testkit` (in-memory), `pk-auth-persistence-jdbi` (Postgres, Flyway
V8), and `pk-auth-persistence-dynamodb` (single-table with DynamoDB native TTL on the row's `ttl`
attribute).

Adapter wiring:

- Spring Boot starter: `@Bean AccessTokenStore` defaulting to noop, with `@ConditionalOnMissingBean`
  so the JDBI and DynamoDB modules (or host beans) take precedence.
- Dropwizard bundle: `PersistenceBindings.accessTokenStore()` defaults to noop, and hosts pass a
  real store via the builder.
- Micronaut adapter: a `@Singleton AccessTokenStore` factory method, overridable via the host's own
  `@Singleton` declaration.

## Consequences

- Pro: server-side logout works end to end with no host-side code beyond binding the JDBI or
  DynamoDB `AccessTokenStore` bean and calling `store.delete(userHandle, jti)` from the logout
  endpoint.
- Pro: user deletion (ADR 0016) becomes a one-call operation:
  `UserDeletionService.deleteUser(handle)` fans out to every listener, including the access-token
  cleanup.
- Pro: no new sealed-result variant is needed. `Revoked` covers both deny-list hits and store
  misses.
- Pro: the noop default keeps the stateless path cost-free. Every validation call still hits
  `exists(...)`, but it is an always-true lambda.
- Con: the store holds one row per issued token. Hosts that issue at high volume (millions per day)
  and do not need fast revocation should stay with `RevocationCheck` and a small deny-list. The
  library does not auto-detect this, and the operator picks the binding.
- Con: `JwtClaims` carries no device identifier, so `PkAuthJwtIssuer` always passes
  `Optional.empty()` for `deviceId` to `record(...)`. Binding issued JWTs to a refresh family or
  device, for "log out this device" granularity, is left to a future ADR.
- Con: the validator's hot path now includes a store lookup. For the noop case this is a
  hash-lookup-then-return, and for JDBI it is one indexed query per validate. Adopters needing the
  absolute lowest validation latency (for example CDN-near edge validation) should benchmark before
  enabling.

## Open follow-ups

- Adding `deviceId` to `JwtClaims` and threading it through `record(...)` becomes meaningful once
  PR 3 (refresh tokens) lands and device-bound sessions are a first-class concept.
- An operator-guide entry for the daily `deleteExpiredBefore(now)` cleanup cron is pending; the
  cron is currently documented only inline.
