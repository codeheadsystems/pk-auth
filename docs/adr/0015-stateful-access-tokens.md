# 15. Stateful access tokens via AccessTokenStore SPI

Date: 2026-05-16

## Status

Accepted.

## Context

Through 1.0, pk-auth issued stateless JWTs (ADR 0005) and exposed a {@link
RevocationCheck} SPI as a deny-list escape hatch: hosts that needed early
invalidation could keep a small in-process set of "revoked jtis" and the
validator would consult it. The pattern works but doesn't match the way every
serious consumer ends up writing the code. Motif's `MotifJwtIssuer`
demonstrates the actual pattern in production use:

1. On every issue, persist the JTI to an `access_tokens` table.
2. On every validate, look the JTI up; if absent, reject.
3. On logout, delete the JTI.
4. On user delete, delete every JTI for that user.

The deny-list shape inverts that: a *positive* allow-list means "this token
was issued by us and has not been deleted" — and "deleted" covers logout,
admin revocation, password reset, account compromise response, and user
deletion uniformly. The cost is one row per issued token plus one read per
validation. For the deployments that need revocability at all, this is the
right cost shape — small, predictable, and equivalent to a session table.

The 1.1.0 release adds the positive-allow primitive without removing the
existing deny-list. Both coexist:

- `RevocationCheck` — fast, in-process deny-list. Right for hosts that issue
  many millions of tokens per day and only want to invalidate a tiny subset
  proactively (e.g. a "session revoked" stream from a security event bus).
- `AccessTokenStore` — durable allow-list. Right for hosts that issue
  meaningfully fewer tokens (admin sessions, mobile clients) and want logout
  to take effect before the JWT's `exp`. This is the paved road.

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

`PkAuthJwtIssuer.issue(JwtClaims)` always calls `store.record(...)` after
signing and before returning the wire token. If `record` throws, issuance
fails — partial state (token returned but unrecorded) is not tolerated.

`PkAuthJwtValidator.validate(String)` calls `store.exists(jti)` after
signature, issuer, audience, and skew checks but alongside the existing
`RevocationCheck`. A `false` return (jti not in store) maps to
`JwtVerificationResult.Revoked` — the same outcome as a deny-list hit, so
consumers don't have to learn a new sealed-result variant.

The default binding is `AccessTokenStore.noop()`: `record` discards,
`exists` returns `true` for every jti, and the delete methods return zero.
This preserves stateless JWT behaviour for hosts that don't bind a real
store, so the "feature is opt-in by binding a different bean" pattern stays
clean — no `TokenMode` enum, no two-place configuration footgun.

Implementations ship in `pk-auth-testkit` (in-memory), `pk-auth-persistence-jdbi`
(Postgres, Flyway V8), and `pk-auth-persistence-dynamodb` (single-table with
DynamoDB native TTL on the row's `ttl` attribute).

Adapter wiring:

- Spring Boot starter — `@Bean AccessTokenStore` defaulting to noop, with
  `@ConditionalOnMissingBean` so JDBI/Dynamo modules (or host beans) win.
- Dropwizard bundle — `PersistenceBindings.accessTokenStore()` defaults to
  noop; hosts pass a real store via the builder.
- Micronaut adapter — `@Singleton AccessTokenStore` factory method,
  overridable via the host's own `@Singleton` declaration.

## Consequences

- **Pro**: Server-side logout works end-to-end with no host-side code
  beyond binding the JDBI/Dynamo `AccessTokenStore` bean and calling
  `store.delete(userHandle, jti)` from the logout endpoint.
- **Pro**: User deletion (ADR 0016) becomes a one-call operation:
  `UserDeletionService.deleteUser(handle)` fans out to every listener
  including the access-token cleanup.
- **Pro**: No new sealed-result variant. `Revoked` covers both deny-list
  hits and store-misses.
- **Pro**: The noop default keeps the stateless path strictly free — every
  validation call still hits `exists(...)` but it's an `always-true` lambda.
- **Con**: One row per issued token. Hosts that issue at high volume
  (millions/day) and don't need fast revocation should stick with
  `RevocationCheck` + a small deny-list. The library does not auto-detect
  this; the operator picks the binding.
- **Con**: The `ttl` field on `JwtClaims` isn't yet a first-class device-id
  channel — when stateful, `record(...)` always passes `Optional.empty()`
  for `deviceId`. A future ADR (when refresh tokens land) extends this
  surface to bind issued JWTs to a refresh family/device for "log out this
  device" granularity.
- **Con**: The validator's hot path now includes a store lookup. For the
  noop case this is a hash-lookup-then-return; for JDBI it's one indexed
  query per validate. Adopters needing the absolute lowest validation
  latency (e.g. CDN-near edge validation) should benchmark before enabling.

## Open follow-ups

- Adding `deviceId` to `JwtClaims` and threading it through `record(...)`
  becomes meaningful once PR 3 (refresh tokens) lands and device-bound
  sessions are a first-class concept.
- Operator-guide entry for the daily `deleteExpiredBefore(now)` cleanup
  cron — currently only documented inline.
