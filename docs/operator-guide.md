# pk-auth Operator Guide

What an operator running pk-auth in production needs to know: secrets, persistence,
observability, rotation, and the most common ways a deployment goes wrong.

## 1. Required environment

pk-auth ships as a JVM library — Spring Boot 4, Dropwizard 5, or Micronaut 4
adapters all consume the same core. A typical production deployment needs:

- **JDK 21** (records, sealed types, virtual threads). Earlier JDKs will not compile.
- **Postgres 16+** (when using `pk-auth-persistence-jdbi`) — Flyway migrations run
  at startup, no manual schema work.
- **DynamoDB** (when using `pk-auth-persistence-dynamodb`) — two tables: a
  single-table `PkAuthCore` carrying every pk-auth auth item plus a separate
  `PkAuthUsers` table for the host-app user records the `UserLookup` SPI reads.
  See ADR 0008 for the table layout.
- **At least one trusted dispatcher** for magic links + OTP if you enable those
  flows. The testkit's `LoggingEmailSender` / `LoggingSmsSender` log secrets to
  stdout; never use them in production.

## 2. Secrets

| Setting | Min length | Notes |
|---|---|---|
| `pkauth.jwt.secret` (HS256) | 32 bytes | Hard fail at boot if shorter. Rotate by issuing a fresh secret and tolerating a grace window (issue + verify in parallel — pk-auth itself does not rotate; the host shoulds run two issuers behind a load balancer until tokens expire). |
| `pkauth.relying-party.id` | n/a | The eTLD+1 (e.g. `example.com`, NOT `auth.example.com`). Cross-subdomain passkeys all bind to this. Once a credential is registered against an RP ID, it cannot be re-registered against a different one without a fresh enrollment. |
| `pkauth.relying-party.origins` | n/a | Strict allow-list of `https://` origins. WebAuthn rejects mismatches; expand the list as you add subdomains. |
| OTP pepper (`pkauth.otp.pepper`) | n/a | Per-deployment pepper for OTP hashes only — OTP codes are hashed with HMAC-SHA256(pepper, code), not Argon2id. (Backup codes use Argon2id with no pepper.) Treat as a long-lived secret; rotating it invalidates every existing OTP hash. |

Recommended: stash secrets in a KMS/Secrets Manager and inject as environment
variables (`PKAUTH_JWT_SECRET`, `PKAUTH_OTP_PEPPER`). The adapters bind both.

## 3. Persistence migrations

### JDBI / Postgres

- Flyway resources live in `pk-auth-persistence-jdbi/src/main/resources/db/migration`.
- Migrations run automatically when the SPI is wired (see ADR 0003).
- The shipped baseline is split across `V1__credentials.sql`,
  `V2__challenges.sql`, `V3__backup_codes.sql`, `V4__otp_codes.sql`, and
  `V5__example_users.sql` — five tables (`credentials`, `challenges`,
  `backup_codes`, `otp_codes`, `users`) with no `pkauth_` prefix.
  `V6__audit_soft_delete.sql` adds the append-only `pkauth_audit_events` table.
  `V7__credentials_hard_delete.sql` drops the `revoked_at` / `revoked_reason`
  columns on `credentials` — credential delete is a hard delete, with the
  audit record captured as a structured log event (`pkauth.credential.deleted`).
  `V8__create_access_tokens.sql` and `V9__create_refresh_tokens.sql` add the
  1.1.0 `access_tokens` and `refresh_tokens` tables; `V10__refresh_tokens_amr.sql`
  adds the `amr` (RFC 8176 authentication-method-reference) column to
  `refresh_tokens`.
- Magic-link tokens are not persisted: the JWT is the credential, and the
  consumed-JTI store is in-memory by default (see `ConsumedJtiStore` SPI for a
  multi-replica override).
- The unique key on credential ID is byte-array shaped — do **not** introduce a
  string-encoded column without a migration.

### DynamoDB

- Two physical tables (see ADR 0008): `PkAuthCore` holds every pk-auth auth item
  (credentials, challenges, backup codes, OTP codes, and the 1.1.0 token rows),
  and `PkAuthUsers` holds the host-app user records the `UserLookup` SPI reads.
  Provision both before the app starts; the adapter does not create them.
- The DynamoDB-native TTL attribute is `ttl` (epoch seconds) — enable TTL on the
  `ttl` attribute of the `PkAuthCore` table. It is set on `Challenge` and
  `OneTimePasscode` items so DynamoDB evicts them after expiry. (Magic-link tokens
  are never persisted, in any backend.)
- 1.1.0 adds `access_tokens` and `refresh_tokens` items on the same `PkAuthCore`
  table (ADR 0015, 0013), both pruned by the native `ttl` attribute. Access-token
  rows set `ttl` to their `expiresAt` epoch second; refresh-token rows set it to
  `expiresAt + cleanupRetention` (default 30 days) so used/revoked rows survive the
  forensic-retention window before the background sweep removes them — matching the
  JDBI cleanup semantics. TTL must be enabled on the table for this to work.
- Capacity-mode: on-demand is recommended for steady reads but bursty registration;
  provisioned only makes sense once you have a stable signing/verification baseline.

### Token-table cleanup (1.1.0)

The new stateful access-token store (ADR 0015) and refresh-token store
(ADR 0013) keep used/revoked rows around for a configurable retention
window so operators have a forensic trail. Schedule a daily cleanup job:

**JDBI / Postgres** — call the SPI methods or run the canonical SQL:

```sql
-- Access tokens: drop rows whose exp has passed.
DELETE FROM access_tokens WHERE expires_at < NOW() - INTERVAL '1 day';

-- Refresh tokens: keep used/revoked rows for the configured retention
-- (default 30 days) so a forensic look-back survives.
DELETE FROM refresh_tokens
 WHERE expires_at < NOW() - INTERVAL '30 days'
   AND (used_at IS NOT NULL OR revoked_at IS NOT NULL);
```

**DynamoDB** — native TTL handles routine expiry asynchronously. If you
need synchronous pruning (operator action / test), call
`DynamoDbAccessTokenStore.deleteExpiredBefore(Instant)` and
`DynamoDbRefreshTokenRepository.deleteExpiredBefore(Instant)` —
both walk the primary items and remove anything past the cutoff.

A daily cron is sufficient for both tables; neither row count grows
unboundedly because TTL is set at issue time.

## 4. Observability

Every ceremony and admin operation emits structured logs at INFO. Suggested fields
to forward into your SIEM:

- `userHandle` (base64url), `challengeId`, `credentialId`
- `ceremony.phase` (`start` / `finish`) and `ceremony.step` (`registration` /
  `authentication`)
- `verification.kind` (`signature` / `originPolicy` / `rpIdPolicy` /
  `counterRegression` / `attestationPolicy`)
- `result` (`success` / `denied:<reason>`)

Counter regression and origin mismatch both surface as INFO log entries with a
distinct `result.denied.reason`. Alert on either — they are signals of credential
cloning or a misconfigured RP.

Recommended dashboards:

- p99 of `registration.finish` / `authentication.finish` (target < 200ms with
  Postgres on the same VPC).
- 4xx by reason on `/auth/passkeys/*` (origin mismatch is almost always config
  drift; counter regression is almost always an issue).
- Backup-code redemption and OTP attempt rates per user (the SPIs already
  rate-limit, but operator-side alerts catch credential-stuffing).

## 5. Rotation and re-enrollment

- **Passkey rotation**: users delete and re-add via `DELETE /auth/admin/credentials/{id}`
  and a fresh registration ceremony. The "last credential" guard returns 409 — that
  is intentional. Encourage users to add a second passkey before removing the first.
- **JWT secret rotation**: roll via the dual-issuer pattern in §2.
- **RP ID change**: a one-way migration. Every existing passkey is invalidated. Plan
  a re-enrollment campaign with backup codes / magic links as the bridge.

## 6. Failure modes worth practicing

| Symptom | Likely cause | First check |
|---|---|---|
| Browser shows "Relying party not registrable" | RP ID doesn't match the page's domain | The `pkauth.relying-party.id` config and the page's actual host |
| 4xx on `authentication.finish` with `counter_regression` | A counter wound back — either credential clone or counter-0 (synced) passkey crossing devices | Inspect the credential's `backupEligible` flag; if true, consider switching the policy to `warn` |
| `Challenge expired` 4xx | Five-minute default TTL elapsed | Often a slow user; do not extend the TTL — re-issue start |
| DynamoDB `ConditionalCheckFailedException` on `takeOnce` | Two clients tried to consume the same challenge | Expected; only one succeeds. If the rate is high, inspect for double-submit on the client |
| Spring Security 7 chain mounts before the pk-auth filter | Filter order regression | Verify `PkAuthSecurityConfig.pkAuthSecurityFilterChain` has the higher precedence in the host's chain |

## 7. Disabling the admin endpoints

The account-admin surface (`/auth/admin/**` — list / rename / delete passkeys,
regenerate backup codes, email / phone verification) lives in the optional
`com.codeheadsystems:pk-auth-admin-api` module. If a deployment drives those
operations out-of-band (an internal console, a separate service) and wants a
smaller public HTTP surface, the admin endpoints can be turned **off by
configuration alone — no source changes to pk-auth**. In every adapter the rule
is the same: the admin routes mount **only when `pk-auth-admin-api` is on the
runtime classpath**. Leave it off and no `/auth/admin/**` routes are registered
(requests get a clean 404); the ceremony, JWT, and refresh endpoints are
unaffected.

| Adapter | How admin is wired | To disable |
|---|---|---|
| Spring Boot (`pk-auth-spring-boot-starter`) | `pk-auth-admin-api` is `compileOnly`; `PkAuthAdminAutoConfiguration` is `@ConditionalOnClass(AdminService)` | Do not add `pk-auth-admin-api` as a runtime dependency (the starter does not pull it transitively) |
| Dropwizard (`pk-auth-dropwizard`) | `pk-auth-admin-api` is `compileOnly`; the bundle mounts `PkAuthAdminResource` only when admin is wired | Omit `pk-auth-admin-api`, **or** register the bundle with the no-admin constructor `new PkAuthBundle(persistence)` |
| Micronaut (`pk-auth-micronaut`) | `pk-auth-admin-api` is `compileOnly`; `PkAuthAdminFactory` is `@Requires(classes = AdminService.class)` and `PkAuthAdminController` is `@Requires(beans = AdminService.class)` | Do not add `pk-auth-admin-api` as a runtime dependency (the adapter does not pull it transitively) |

For Maven/Gradle consumers this is purely a dependency decision in the host
application — the admin module is opt-in. The three example apps under
`examples/` declare `pk-auth-admin-api` explicitly because they exercise the full
admin walkthrough; a production host that wants the ceremony surface only simply
leaves that line out.

> **Note (Micronaut).** Keep `PkAuthAdminFactory` (the `@Requires`-gated
> `AdminService` bean) separate from `PkAuthFactory`. Because Micronaut's
> generated bean definition for a `@Factory` references the return types of its
> factory methods, hosting the optional `AdminService` bean on the main factory
> would make `PkAuthFactory` unloadable when `pk-auth-admin-api` is absent
> (`NoClassDefFoundError` on the first ceremony request). The split keeps the
> always-on factory free of any reference to the optional module.

## 8. Threat model

See `docs/threat-model.md` for the formal STRIDE pass.
