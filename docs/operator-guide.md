# pk-auth Operator Guide

What an operator running pk-auth in production needs to know: secrets, persistence, observability,
rotation, and the most common ways a deployment goes wrong.

## 1. Required environment

pk-auth ships as a JVM library. The Spring Boot 4, Dropwizard 5, and Micronaut 4 adapters all
consume the same core. A typical production deployment needs:

- JDK 21 (records, sealed types, virtual threads). Earlier JDKs do not compile the library.
- Postgres 16+ (when using `pk-auth-persistence-jdbi`). The host runs the shipped Flyway
  migrations; no adapter runs them (see §3).
- DynamoDB (when using `pk-auth-persistence-dynamodb`), with two tables: a single-table
  `PkAuthCore` carrying every pk-auth auth item, plus a separate `PkAuthUsers` table for the
  host-app user records the `UserLookup` SPI reads. See ADR 0008 for the table layout.
- At least one trusted dispatcher for magic links and OTP when those flows are enabled. The
  testkit's `LoggingEmailSender` and `LoggingSmsSender` log secrets to stdout and are never used in
  production.

## 2. Secrets

| Setting | Min length | Notes |
|---|---|---|
| `pkauth.jwt.secret` (HS256) | 32 bytes | Hard fail at boot if shorter. Rotation issues a fresh secret and tolerates a grace window (issue and verify in parallel). pk-auth itself does not rotate; the host runs two issuers behind a load balancer until tokens expire. |
| `pkauth.relying-party.id` | n/a | The eTLD+1 (for example `example.com`, not `auth.example.com`). Cross-subdomain passkeys all bind to this value. A credential registered against an RP ID cannot be re-registered against a different one without a fresh enrolment. |
| `pkauth.relying-party.origins` | n/a | Strict allow-list of `https://` origins. WebAuthn rejects mismatches, so the list expands as subdomains are added. |
| OTP pepper (`pkauth.otp.pepper`) | 16 bytes decoded (32+ recommended) | Base64-encoded per-deployment pepper for OTP hashes only: OTP codes are hashed with HMAC-SHA256(pepper, code), not Argon2id. (Backup codes use Argon2id with no pepper.) Hard fail at boot if the value is not valid Base64 or decodes to fewer than 16 bytes. If unset, the adapter auto-generates a throwaway per-startup pepper only when `pkauth.dev-mode=true` (dev only: it invalidates outstanding OTPs across restarts and across cluster instances); with dev-mode off, an unset pepper is a hard boot failure. The pepper is a long-lived secret, and rotating it invalidates every existing OTP hash. |

Secrets belong in a KMS or Secrets Manager, injected as environment variables
(`PKAUTH_JWT_SECRET`, `PKAUTH_OTP_PEPPER`). The adapters bind both.

### User Verification (UV)

`CeremonyConfig.userVerification` defaults to `REQUIRED`. With this default WebAuthn4J enforces the
asserted `flagUV` on every registration and authentication, so each ceremony must carry a
per-ceremony biometric or PIN. This is what makes a passkey a genuine factor: something the user
has plus something the user is or knows.

Relaxing the setting to `PREFERRED` or `DISCOURAGED` accepts a present-but-unverified authenticator
(mere user-presence, no biometric or PIN). A passkey then degrades to "something the user has"
alone, which materially weakens the factor for every user. The only standard reason to opt out is
supporting UV-incapable roaming hardware security keys, and a deployment that opts out for that
reason scopes the relaxation narrowly because of the trade-off above.

### COSE signature algorithms (crypto-agility)

Two ceremony knobs control which COSE signature algorithms are used (ADR 0019):

- `pkauth.ceremony.offered-algorithms` is advertised to the authenticator in registration
  create-options. Default: `[ES256, EdDSA, RS256]`.
- `pkauth.ceremony.accepted-algorithms` is the verify allow-list; a credential whose algorithm is
  absent is rejected on registration. Default (and the enforced superset):
  `[ES256, EdDSA, RS256, ES384, RS384]`.

`offered` must be a subset of `accepted`. The defaults are the historical union, so leaving them
unset changes nothing. Either list can be narrowed (for example to drop RSA), but narrowing
`accepted` can reject already-registered credentials that use a removed algorithm. A re-enrolment
campaign (see `AdminService.listCredentialsByAlgorithm`) precedes any narrowing. In Spring and
Micronaut these bind from `application.yml`; in Dropwizard they are the `PkAuthConfig.Ceremony`
record's `offeredAlgorithms` / `acceptedAlgorithms` components. All three example apps set them
explicitly (to the defaults) as living documentation. No post-quantum signature algorithm is
available to select yet; see the "Post-quantum readiness" section of `docs/threat-model.md`.

## 3. Persistence migrations

### JDBI / Postgres

- Flyway resources live in `pk-auth-persistence-jdbi/src/main/resources/db/migration`.
- No adapter runs these migrations. The host runs them by adding `classpath:db/migration` from this
  artefact to its own Flyway locations, targeting `PkAuthJdbiSchema.CURRENT_SCHEMA_VERSION`.
  `PkAuthJdbiSchema.migrateForDevelopment(DataSource)` exists for demos and integration tests only.
- The shipped baseline is split across `V1__credentials.sql`, `V2__challenges.sql`,
  `V3__backup_codes.sql`, `V4__otp_codes.sql`, and `V5__example_users.sql`: five tables
  (`credentials`, `challenges`, `backup_codes`, `otp_codes`, `users`) with no `pkauth_` prefix.
  `V6__audit_soft_delete.sql` adds the append-only `pkauth_audit_events` table.
  `V7__credentials_hard_delete.sql` drops the `revoked_at` / `revoked_reason` columns on
  `credentials`: credential delete is a hard delete, with the audit record captured as a structured
  log event (`pkauth.credential.deleted`). `V8__create_access_tokens.sql` and
  `V9__create_refresh_tokens.sql` add the 1.1.0 `access_tokens` and `refresh_tokens` tables;
  `V10__refresh_tokens_amr.sql` adds the `amr` (RFC 8176 authentication-method-reference) column to
  `refresh_tokens`. `V11` and `V12` follow; the migration directory lists the current set.
- Magic-link tokens are not persisted: the JWT is the credential, and the consumed-JTI store is
  in-memory by default (see the `ConsumedJtiStore` SPI for a multi-replica override).
- The unique key on credential ID is byte-array shaped. Introducing a string-encoded column for it
  requires a migration.

### DynamoDB

- Two physical tables exist (see ADR 0008): `PkAuthCore` holds every pk-auth auth item (credentials,
  challenges, backup codes, OTP codes, and the 1.1.0 token rows), and `PkAuthUsers` holds the
  host-app user records the `UserLookup` SPI reads. Both tables are provisioned before the app
  starts; the adapter does not create them.
- The DynamoDB-native TTL attribute is `ttl` (epoch seconds), and TTL is enabled on the `ttl`
  attribute of the `PkAuthCore` table. The attribute is set on challenge (`ChallengeItem`) and OTP
  (`OtpItem`) items so DynamoDB evicts them after expiry. (Magic-link tokens are never persisted, in
  any backend.)
- 1.1.0 adds `access_tokens` and `refresh_tokens` items on the same `PkAuthCore` table (ADR 0015,
  0013), both pruned by the native `ttl` attribute. Access-token rows set `ttl` to their
  `expiresAt` epoch second. Refresh-token rows set it to `expiresAt + cleanupRetention` (default 30
  days), so used and revoked rows survive the forensic-retention window before the background sweep
  removes them, matching the JDBI cleanup semantics. TTL must be enabled on the table for this to
  work.
- Capacity mode: on-demand is recommended for steady reads but bursty registration. Provisioned
  capacity makes sense only once a stable signing and verification baseline exists.

### Token-table cleanup (1.1.0)

The stateful access-token store (ADR 0015) and the refresh-token store (ADR 0013) keep used and
revoked rows for a configurable retention window so operators have a forensic trail. A daily
cleanup job removes expired rows.

On JDBI / Postgres, the job calls the SPI methods or runs the canonical SQL:

```sql
-- Access tokens: drop rows whose exp has passed.
DELETE FROM access_tokens WHERE expires_at < NOW() - INTERVAL '1 day';

-- Refresh tokens: keep used/revoked rows for the configured retention
-- (default 30 days) so a forensic look-back survives.
DELETE FROM refresh_tokens
 WHERE expires_at < NOW() - INTERVAL '30 days'
   AND (used_at IS NOT NULL OR revoked_at IS NOT NULL);
```

On DynamoDB, native TTL handles routine expiry asynchronously. Synchronous pruning (operator action
or test) calls `DynamoDbAccessTokenStore.deleteExpiredBefore(Instant)` and
`DynamoDbRefreshTokenRepository.deleteExpiredBefore(Instant)`, both of which walk the primary items
and remove anything past the cutoff.

A daily cron is sufficient for both tables. Neither row count grows unboundedly, because TTL is set
at issue time.

## 4. Observability

Every ceremony and admin operation emits structured logs at INFO. Suggested fields to forward into a
SIEM:

- `userHandle` (base64url), `challengeId`, `credentialId`
- `ceremony.phase` (`start` / `finish`) and `ceremony.step` (`registration` / `authentication`)
- `verification.kind` (`signature` / `originPolicy` / `rpIdPolicy` / `counterRegression` /
  `attestationPolicy`)
- `result` (`success` / `denied:<reason>`)

Counter regression and origin mismatch both surface as INFO log entries with a distinct
`result.denied.reason`. Both are signals of credential cloning or a misconfigured RP, and both
warrant alerts.

Recommended dashboards:

- p99 of `registration.finish` / `authentication.finish` (target < 200ms with Postgres on the same
  VPC).
- 4xx by reason on `/auth/passkeys/*` (origin mismatch is almost always config drift; counter
  regression is almost always an issue).
- Backup-code redemption and OTP attempt rates per user (the SPIs already rate-limit, but
  operator-side alerts catch credential-stuffing).

## 5. Rotation and re-enrolment

- Passkey rotation: users delete and re-add via `DELETE /auth/admin/credentials/{id}` and a fresh
  registration ceremony. The "last credential" guard returns 409. A user adds a second passkey
  before removing the first.
- JWT secret rotation: rolls via the dual-issuer pattern in §2.
- RP ID change: a one-way migration. Every existing passkey is invalidated. The change needs a
  re-enrolment campaign with backup codes or magic links as the bridge.

## 6. Failure modes

| Symptom | Likely cause | First check |
|---|---|---|
| Browser shows "Relying party not registrable" | RP ID does not match the page's domain | The `pkauth.relying-party.id` config and the page's actual host |
| 4xx on `authentication.finish` with `counter_regression` | A counter wound back: either a credential clone or a counter-0 (synced) passkey crossing devices | The credential's `backupEligible` flag; if true, consider switching the policy to `warn` |
| `Challenge expired` 4xx | Five-minute default TTL elapsed | Often a slow user; the remedy is to re-issue `start`, not to extend the TTL |
| DynamoDB `ConditionalCheckFailedException` on `takeOnce` | Two clients tried to consume the same challenge | Expected; only one succeeds. If the rate is high, the client, for double-submit |
| Spring Security 7 chain mounts before the pk-auth filter | Filter order regression | The starter's `pkAuthSecurityFilterChain` bean (`PkAuthWebAutoConfiguration`, `@Order(HIGHEST_PRECEDENCE + 10)`) has the higher precedence in the host's chain |

## 7. Disabling the admin endpoints

The account-admin surface (`/auth/admin/**`: list, rename, and delete passkeys, regenerate backup
codes, email and phone verification) lives in the optional `com.codeheadsystems:pk-auth-admin-api`
module. A deployment that drives those operations out-of-band (an internal console or a separate
service) and wants a smaller public HTTP surface turns the admin endpoints off by configuration
alone, with no source changes to pk-auth. In every adapter the rule is the same: the admin routes
mount only when `pk-auth-admin-api` is on the runtime classpath. When it is absent, no
`/auth/admin/**` routes are registered (requests get a clean 404), and the ceremony, JWT, and
refresh endpoints are unaffected.

| Adapter | How admin is wired | Disabling |
|---|---|---|
| Spring Boot (`pk-auth-spring-boot-starter`) | `pk-auth-admin-api` is `compileOnly`; `PkAuthAdminAutoConfiguration` is `@ConditionalOnClass(AdminService)` | `pk-auth-admin-api` absent from the runtime dependencies (the starter does not pull it transitively) |
| Dropwizard (`pk-auth-dropwizard`) | `pk-auth-admin-api` is `compileOnly`; the bundle mounts `PkAuthAdminResource` only when admin is wired | `pk-auth-admin-api` omitted, or the bundle registered with the no-admin constructor `new PkAuthBundle(persistence)` |
| Micronaut (`pk-auth-micronaut`) | `pk-auth-admin-api` is `compileOnly`; `PkAuthAdminFactory` is `@Requires(classes = AdminService.class)` and `PkAuthAdminController` is `@Requires(beans = AdminService.class)` | `pk-auth-admin-api` absent from the runtime dependencies (the adapter does not pull it transitively) |

For Maven and Gradle consumers this is purely a dependency decision in the host application, because
the admin module is opt-in. The three example apps under `examples/` declare `pk-auth-admin-api`
explicitly because they exercise the full admin walkthrough. A production host that wants the
ceremony surface only leaves that line out.

### Micronaut factory split

`PkAuthAdminFactory` (the `@Requires`-gated `AdminService` bean) is kept separate from
`PkAuthFactory`. Micronaut's generated bean definition for a `@Factory` references the return types
of its factory methods, so hosting the optional `AdminService` bean on the main factory would make
`PkAuthFactory` unloadable when `pk-auth-admin-api` is absent (`NoClassDefFoundError` on the first
ceremony request). The split keeps the always-on factory free of any reference to the optional
module.

## 8. Transport security and post-quantum exposure

pk-auth's own primitives are post-quantum aware (see the "Post-quantum readiness" section of
`docs/threat-model.md`), but the one **harvest-now, decrypt-later** risk in a real
deployment lies outside this library. An adversary who records TLS sessions today can decrypt them
later, once a cryptographically relevant quantum computer (CRQC) breaks the classical key exchange
that protected them. Those sessions carry pk-auth's bearer material in transit: access JWTs,
refresh tokens, magic-link URLs, and OTP codes. A WebAuthn assertion (challenge-response) leaves
nothing to harvest, but a recorded ciphertext is harvestable.

TLS terminates at the edge (load balancer, reverse proxy, or CDN), not in pk-auth. The mitigation is
therefore an operator action and not a library change:

1. Enable a hybrid post-quantum key exchange at the TLS terminator or CDN. The current deployable
   standard is the hybrid group `X25519MLKEM768` (X25519 plus ML-KEM-768 / FIPS 203), which stays
   classically secure even if the PQC half is later faulted, and which recent OpenSSL and BoringSSL,
   major CDNs, and current browsers already support. The setting goes wherever TLS terminates:
   - Nginx/OpenSSL 3.5+: include the hybrid group in `ssl_ecdh_curve` / `Groups`/`Curves` (for
     example `X25519MLKEM768:X25519`).
   - Behind a CDN (Cloudflare, etc.): enable post-quantum or hybrid key agreement in the edge TLS
     settings.
2. Keep token TTLs short. A short access-token TTL (default 1 hour) and rotating refresh tokens
   bound the value of any session an attacker does eventually decrypt.

This does not change anything pk-auth signs or stores; it hardens the channel the tokens travel
over. No pk-auth setting controls it, because it lives entirely in the TLS-terminating layer.

## 9. Threat model

See `docs/threat-model.md` for the formal STRIDE pass.
