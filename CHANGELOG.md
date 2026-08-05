# Changelog

All notable changes to pk-auth are recorded here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The 0.x line is treated as a single pre-stable development series — see
`docs/stability.md` and the early ADRs for context. This changelog starts at the
1.0.0 stabilisation cut; for 0.x history consult `git log` against the relevant
tags.

## [Unreleased]

A security release driven by a full-project audit. Every entry below closes a
finding from that review.

### Security

- **Magic-link `SendResult.Sent` no longer carries the login token.** The record
  component was named `tokenJti` but held the complete signed magic-link JWT — a
  bearer credential that authenticates as the user without inbox access. A host
  logging or echoing what its name advertised as an opaque correlation id was
  publishing a working login credential. `Sent` now carries the real `jti`; the
  token reaches only the configured `EmailSender`. **Breaking:** the component is
  renamed `tokenJti` → `jti` *and* its value changes, so hosts that recovered the
  token from the result (e.g. to render their own email) must instead capture it
  in a `MessageFormatter` / `EmailSender`. `startLogin`'s enumeration-resistant
  short-circuit paths continue to return `Sent("")`.
- **Usernames are bounded and the in-memory rate-limiter caches can no longer grow
  without limit.** Nothing capped username length (the JDBI column is Postgres
  `TEXT`), and both Caffeine caches used `expireAfterWrite` with no
  `maximumSize` — so on the `permitAll` start endpoints, a caller varying its
  username grew the maps with its own key variety rather than with the number of
  real users, and every distinct key was retained for the full window.
  `StartRegistrationRequest.MAX_USERNAME_LENGTH` (256, enough for an email
  address) now bounds both start requests, and `InMemoryCeremonyRateLimiter` /
  `InMemoryWindowCounter` cap their maps at
  `DEFAULT_MAX_TRACKED_KEYS` (100 000). An over-long username is refused as a
  clean **400** — covered by an adapter-level test asserting the refusal reaches
  the client as a 400 and not a 500. `StartAuthenticationRequest` still accepts a
  `null` username (the usernameless / discoverable-credential flow).

## [2.2.0] — 2026-06-27

A security-and-correctness release driven by two rounds of adversarial review.
The headline is a set of fixes to the magic-link, OTP, and JWT alt-flows plus
server-side enforcement of per-request user verification. Passkey-core hosts
upgrade by bumping the version; **hosts that implement the `OtpRepository` SPI
directly must add the new `Instant now` parameter** to `findLatestActive` (see
Changed), and JDBI hosts pick up one new Flyway migration (V11).

### Security

- **Magic-link tokens can no longer be replayed or used as bearer tokens.** Links
  are issued with a dedicated short TTL (15 min, owned by `MagicLinkService`
  rather than inherited from the 1-hour access-token TTL), the consumed-JTI
  retention is enforced to be ≥ the token TTL at construction, and tokens carry a
  dedicated audience (`MagicLinkService.DEFAULT_AUDIENCE`) so the resource-server
  validator rejects them — a magic-link token can no longer stand in for an API
  access token.
- **Magic-link login no longer delivers to attacker-supplied addresses.**
  `MagicLinkService.startLogin` sends only to the address bound to the resolved
  user via `UserLookup#emailFor`, never the caller-supplied address
  (account-takeover fix).
- **Per-request user verification is enforced server-side.** A per-ceremony
  `userVerification=REQUIRED` (e.g. step-up) is persisted on the challenge and
  enforced at finish as the stricter of {global config, per-request}, so it can
  no longer be silently downgraded by a non-cooperative client.
- **JWT claim-override hardening.** `JwtClaims` rejects caller-supplied
  `additionalClaims` that collide with reserved claims (`iss/sub/aud/exp/jti/
  pkauth.*`), closing an impersonation / TTL-bypass vector.
- **OTP brute-force off-by-one fixed** so exactly `maxAttempts` guesses are
  compared, and admin OTP `AttemptsExceeded` now surfaces as HTTP 429 rather than
  a 200 with the failure buried in the body.
- **No secret leakage:** `JwtKeyset.es256` puts only public JWKs in
  `verificationSource()` (a host publishing a JWKS endpoint can't leak the
  signing key), and the `TwilioSmsSender` skeleton no longer echoes its account
  SID / sender number into exception messages.

### Added

- `Retry-After: 60` on rate-limited (429) ceremony endpoints
  (registration/authentication start + finish), via a new `headers` component on
  the exported `CeremonyResponse` wire record (back-compatible two-arg
  constructor); all three adapters copy it onto the HTTP response.
- `MagicLinkService.Dependencies.ofDedicatedAudience(...)` and
  `MagicLinkService.DEFAULT_AUDIENCE` for the dedicated-audience wiring above;
  all three adapters wire the magic-link service through it.
- `ChallengeRecord` carries the resolved `userVerification` requirement (with a
  back-compatible four-arg constructor); JDBI persists it via **Flyway migration
  V11** (`challenges.user_verification`, schema version → `11`).

### Changed

- **`OtpRepository.findLatestActive` now takes an `Instant now` parameter**
  (breaking for direct SPI implementers) so each backend filters expired codes
  against the host `ClockProvider` rather than the database wall clock.
- Magic-link tokens are no longer recorded in the `AccessTokenStore` (the
  dedicated magic-link issuer uses a no-op store).
- Spring: the pk-auth `/auth/**` security filter chain is pinned to an early
  `@Order` so a host catch-all chain can't shadow it, and the JWT filter is no
  longer auto-registered as a global servlet filter (it runs only inside the
  chain).
- Maintenance: routine Dependabot bumps (Gradle, gh-actions, npm), and the
  Spotless version pin / docs were reconciled (the project tracks the 8.x line).

### Fixed

- DynamoDB refresh-token `create()` writes its primary + index items in a single
  atomic `TransactWriteItems`, so a partial write can't orphan a primary that a
  family revoke would later miss; a duplicate `refreshId` now surfaces as
  `PkAuthPersistenceException`.
- DynamoDB family/user revoke uses a scalar conditional `UpdateItem` instead of a
  read-modify-write that could clobber a concurrent `usedAt`; the in-memory
  testkit no longer does a cross-key write inside `ConcurrentHashMap.compute`.
- JDBI `updateSignCount` records `last_used_at` for sync passkeys that always
  report `signCount = 0` (a strict-regression check is still enforced).
- `AAGUID` is null-guarded in `persistRegistration` so a null AAGUID returns a
  sealed `RegistrationResult` instead of throwing across the result boundary.

## [2.1.0] — 2026-06-23

A backward-compatible minor release. The headline is **crypto-agility and
post-quantum readiness for passkey signature algorithms** (ADR 0019): the
two divergent hardcoded COSE algorithm lists are replaced by a single
operator-configurable source of truth, and there is now a way to see which
algorithm each stored credential uses. No public API is removed and the HTTP
`/auth/**` wire contract is unchanged, so hosts upgrade by bumping the version.

To be precise about scope: **no post-quantum signature algorithm is added** —
PQC for passkeys is gated end-to-end by authenticator hardware, CTAP2/FIDO2,
the WebAuthn/COSE registry, and WebAuthn4J's verifier, none of which yet
standardize one. The goal here is crypto-agility (clean removal of the
migration obstacles) and honest documentation, not new algorithms.

### Added

- **Crypto-agility for passkey signature algorithms** (ADR 0019). A new
  framework-neutral `CoseAlgorithm` enum, and `CeremonyConfig` now carries two
  ordered lists: `offeredAlgorithms` (advertised in registration create-options)
  and `acceptedAlgorithms` (enforced on the WebAuthn4J verify path).
  `acceptedAlgorithms` is authoritative and `offeredAlgorithms` must be a subset.
  Both the create-options ceremony and the verify path derive their lists from
  this single config, replacing the two previously-divergent hardcoded lists, so
  operators can narrow either without code changes. A new 5-arg `CeremonyConfig`
  convenience constructor applies backward-compatible defaults — accepted =
  `ES256, EdDSA, RS256, ES384, RS384` (the union of everything previously
  accepted, so no already-registered credential can fail verification); offered =
  `ES256, EdDSA, RS256` (the historical create-options subset) — so every
  existing call site compiles and behaves identically.
- **Per-credential algorithm visibility.**
  `CredentialAlgorithms.coseAlgorithm(record)` decodes the COSE algorithm already
  embedded in a stored public key (**no schema change**), and
  `AdminService.listCredentialsByAlgorithm(actor, target, coseAlgorithm)` reports
  which stored credentials use a given algorithm — the read side a future
  "re-enroll off algorithm X" campaign drives off.
- **Offered/accepted algorithm configuration wired through every adapter.** The
  Spring Boot starter, Dropwizard, and Micronaut adapters (and the matching demo
  `application.yml` files) expose the two algorithm lists as host config, so the
  create-options and verify lists can be tuned without touching code.

### Changed

- **Honest JWT crypto framing** (ADR 0019, documentation only — no behavior
  change). The HS256-vs-ES256 choice is re-documented as a trust-topology
  decision rather than a dev-vs-prod one: HMAC-SHA256 is *not* broken by Shor and
  retains ~128-bit security under Grover with the enforced ≥ 256-bit key, making
  it the quantum-conservative default for a single-issuer/single-verifier
  deployment; ES256 JWTs exist for untrusted third-party verification and carry
  Shor exposure bounded by the short token TTL. See `docs/threat-model.md` and
  `docs/operator-guide.md`.
- **Build / CI.** The Playwright end-to-end suites under `examples/` are now
  wired into each demo's `check` via an opt-in `e2eTest` task (gated on
  `PK_RUN_E2E=1` / `-PrunE2e`, so the default gate stays fast and Chrome-free),
  and CI runs all three demos in a dedicated `e2e` matrix job.

## [2.0.0] — 2026-06-13

The first 2.x release. The bulk of the work is correctness, hardening, and
maintainability; the major-version bump is driven by **one breaking change to
the embedded Java API** — the `start*` ceremony methods (described under
Changed). The HTTP `/auth/**` wire contract (request/response bodies and status
codes) is unchanged, so deployments that integrate through the Spring /
Dropwizard / Micronaut adapters and the JSON API need no code changes.

### Changed

- **Breaking (embedded API only): `start*` ceremonies now return sealed result
  sums.** `PasskeyAuthenticationService.startRegistration` /
  `startAuthentication` return `StartRegistrationResult` /
  `StartAuthenticationResult` (`Started | RateLimited`) instead of the bare
  response envelope, mirroring the `finish*` ceremonies, and the
  `CeremonyRateLimitedException` type is removed. A rate-limit refusal is now a
  value every adapter pattern-matches (compile-checked exhaustiveness) rather
  than an exception thrown across the boundary. Hosts using the Spring /
  Dropwizard / Micronaut adapters are unaffected; only code calling
  `PasskeyAuthenticationService` directly must switch on the result. The
  `200` / `429` wire responses are identical to before.
- **Host→domain config translation is centralized.** `RelyingPartyConfig.from(…)`
  and `CeremonyConfig.from(…)` carry the shared validation and conservative
  default-coalescing (UV `REQUIRED`, counter-regression `REJECT`) the three
  adapter factories previously duplicated; an unset knob can only resolve to the
  secure default.
- **The persistence-failure response envelope is centralized** in
  `PkAuthPersistenceResponse` (HTTP `503`, body
  `{"error":"persistence_failure","operation":…}`), so all three adapters emit a
  byte-identical body and a backend outage cannot leak a framework-default 500.
- **Build / CI.** SonarQube Cloud was dropped for the JVM modules in favour of
  native JaCoCo line + branch coverage gates (ADR 0018); it is retained for the
  TypeScript browser SDK. CI now fails if `PKAUTH_SKIP_TESTCONTAINERS=1` leaks
  into the gate, adds a `workflow_dispatch` trigger for on-demand runs, and skips
  the secret-dependent SonarQube / Stryker steps on Dependabot PRs.

### Added

- **Passkey-only hosts can boot without the alt-flow SPIs** (backup-codes / OTP /
  magic-link), in the admin API and Spring starter.
- **Config range validation** on the OTP, backup-code, and magic-link `Config`
  records — non-positive TTLs, attempt caps, and rate limits are rejected at
  construction instead of producing never-verifiable or instantly-expired codes.
- **Concurrent consume-once acceptance scenarios** for OTP and backup codes in
  the testkit (`OtpRepositoryScenarios`, `BackupCodeRepositoryScenarios`), run
  against real Postgres and DynamoDB Local — the atomic single-use guarantee is
  now proven for those flows, not just refresh tokens.

### Fixed

- **DynamoDB refresh-token rotation no longer scorches a token family on a
  transient error.** A `TransactionCanceledException` is treated as a
  replay/race (revoking the family) only when the parent's freshness condition
  actually failed (`ConditionalCheckFailed`); throughput / transaction-conflict /
  validation cancellations are rethrown as a retryable 5xx, and an
  indeterminable reason fails closed.
- **Ceremony user-verification now defaults to `REQUIRED`,** and the UV /
  resident-key / attestation / counter-regression knobs are surfaced through the
  Spring properties.
- **DynamoDB maintenance scans** (`deleteExpiredBefore`) are constrained with a
  server-side `begins_with(pk, …)` filter instead of reading the whole shared
  single table.
- **OTP no-active-OTP branch** drops a misleading constant-time self-compare; the
  throwaway HMAC that equalizes response timing is kept.
- **Admin phone-verification** maps the `SendResult` sum with an exhaustive
  switch instead of an unchecked downcast.
- Hardened CBOR / converter robustness and added end-to-end forged / replayed
  ceremony coverage.

### Security

- **esbuild forced to ≥ 0.28.1** to clear GHSA-gv7w-rqvm-qjhr (HIGH). It is a
  build-time, dev-only transitive dependency of the browser SDK (never shipped in
  the published bundle), and the advisory targets esbuild's Deno module, so the
  practical exposure was low — but the bump clears the advisory at the source.
- **Browser SDK base64url** no longer uses a ReDoS-shaped regex (SonarQube
  S5852 / CWE-1333); `encode` / `decode` use `replaceAll` with string literals,
  byte-identical output.
- **Documentation corrections to security-relevant behaviour.** OTP codes are
  hashed with HMAC-SHA256 + a server-side pepper (not Argon2id); the
  `userVerification = REQUIRED` default and the ≥ 16-byte OTP pepper requirement
  are now documented in the threat model and operator guide.

## [1.3.1] — 2026-06-06

Patch release: a browser-SDK build fix, a Micronaut admin toggle, and
supply-chain hardening. No wire-format or API-breaking changes.

### Added

- **Micronaut: the admin endpoints can now be disabled.** A new
  configuration toggle lets a Micronaut host opt out of mounting
  `PkAuthAdminController` (passkey list/rename/delete, etc.) while keeping
  the core auth endpoints, mirroring the disable switch the other framework
  integrations already expose. See `docs/operator-guide.md`.

### Fixed

- **Browser SDK builds under TypeScript 6.0.** The dev-dependency bump to
  TypeScript 6.0 broke the `tsup` `.d.ts` pipeline with `TS5101`
  (the injected `baseUrl` is now a deprecation error). Adding
  `ignoreDeprecations: "6.0"` to the SDK `tsconfig.json` restores the build;
  the ESM/CJS/DTS bundle, `tsc --noEmit`, and all vitest tests pass under
  TS 6.0.

### Security

- **Dependency and CI/CD supply-chain hardening.**
  - Every GitHub Actions `uses:` is pinned to a full commit SHA (version in a
    trailing comment) instead of a mutable `@vN` tag — most importantly the
    third-party `softprops/action-gh-release` in the privileged release job.
  - The Gradle distribution is pinned via `distributionSha256Sum` in the
    wrapper, with a `wrapper-validation` step in CI verifying
    `gradle-wrapper.jar`.
  - `actions/dependency-review-action` runs as a PR gate
    (`fail-on-severity: high`) to block newly introduced dependencies with
    known high-severity advisories.
  - Dependabot now covers the npm ecosystem (the published browser SDK and
    each demo's Playwright e2e suite) and gates auto-merge on update type, so
    only patch/minor bumps are auto-approved and Actions updates never
    auto-merge.
  - The build/distribution trust boundary and these mitigations are
    documented.

### Changed

- **Gradle dependency verification (`verification-metadata.xml`) was not
  retained.** It was introduced during the supply-chain work and then
  removed: with Dependabot auto-merging Gradle bumps, the checksum file would
  have to be regenerated unattended from whatever was just downloaded
  (notarizing rather than vetting), and it broke the build on every bump
  because a version-catalog bump cannot update the checksums. Protection
  against malicious dependency *releases* is provided by
  `dependency-review-action`'s advisory database instead. The SHA-pinned
  Actions, pinned Gradle distribution, and dependency-review gate above are
  retained.

### Dependencies

- Routine Dependabot bumps across the dev/runtime dependency groups (Gradle
  and npm) and GitHub Actions.

## [1.3.0]  — 2026-06-03

Security-review follow-ups (hardening; no known exploit in the items below).

### Added

- **Refresh tokens carry the original `amr` through rotation.**
  `RefreshTokenService.issue(UserHandle, String, Optional, List<String>)`
  records the RFC 8176 authentication method references on the refresh
  family, and every rotation propagates them verbatim, so an access token
  minted from `POST /auth/refresh` reflects how the session was first
  established (e.g. `["pkauth","webauthn"]`) instead of a generic
  `["user"]`. `RefreshTokenRecord` and `RotatedClaims` gain an `amr`
  field; persisted as the `amr` column (JDBI, Flyway **V10**) and the
  `amr` attribute (DynamoDB). The previous three-arg
  `issue(UserHandle, String, Optional)` is **deprecated** (defaults `amr`
  to `["user"]`, preserving prior behavior).
- `ChallengeStoreScenarios` in `pk-auth-testkit`: a shared SPI compliance
  suite asserting `ChallengeStore.takeOnce` is single-use, including a
  concurrent "exactly one winner" race test, now driven against the
  in-memory, JDBI/Postgres, and DynamoDB backends.

### Changed

- **`ChallengeId` is now an opaque random handle, decoupled from the
  challenge bytes.** Previously the store key was
  `base64url(challenge)`; it is now a random UUID
  (`ChallengeId.random()`). Finish-time validation still enforces the
  cryptographic binding by byte-comparing the stored challenge against
  the bytes the authenticator signed (and WebAuthn4J re-checks the same
  challenge), so the store key no longer reveals or depends on the
  challenge. No wire-format change; the browser SDK already round-trips
  the id. `ChallengeGenerator.idOf(byte[])` and the internal
  `ChallengeValidation.IdMismatch` variant are removed.
- **`PkAuthJwtValidator` (stateful mode) rejects `jti`-less tokens.** When
  a non-noop `AccessTokenStore` is bound, a validly-signed token with no
  `jti` now returns `MissingClaim("jti")` instead of bypassing the
  revocation gate. (Carried over from 1.2.0's fix; the validator now
  detects stateful mode up front.)
- **DynamoDB refresh rotation uses a conditional `UpdateItem`.**
  `rotateAtomically` now marks the parent used via a partial conditional
  update (`ignoreNullsMode(SCALAR_ONLY)`) instead of a full-item PUT from
  a prior read — it no longer reads the parent first and can't clobber a
  concurrently-written parent attribute. Behavior is unchanged; the
  freshness condition (incl. the numeric-`ttl` expiry compare from 1.2.0)
  is preserved.

### Documentation

- Documented that the stateless access-token TTL is the effective
  revocation window (`JwtConfig`), that `AccessTokenStore.exists` must
  fail closed on outage, that custom `RevocationCheck` deny-lists must
  handle a `null` jti, and that the Spring JWT filter is additive (never
  clears a pre-existing `SecurityContext`).

### Distribution

- **The browser SDK is now published to npm as
  [`@pk-auth/passkeys-browser`](https://www.npmjs.com/package/@pk-auth/passkeys-browser)
  at `1.3.0`** — its first npm release. The SDK version tracks the pk-auth
  server release it speaks to, so `1.3.0` matches this release's Maven
  Central artifacts. Install with `npm install @pk-auth/passkeys-browser`.
  See [`RELEASE.md`](./RELEASE.md) for the publish steps. (The example
  apps still consume the SDK via a relative `dist/` import built by
  Gradle, not the published package.)

## [1.2.0] — 2026-06-02

### Security

- **DynamoDB refresh-token rotation now compares expiry numerically, not
  lexically.** `DynamoDbRefreshTokenRepository.rotateAtomically` gated the
  atomic-rotate `ConditionExpression` on `expiresAtIso > :now`, comparing two
  `Instant.toString()` strings. That output is variable-precision (the
  fractional-seconds field is dropped when zero), so a bytewise `>` sorts
  `…:00Z` *after* `…:00.000001Z` and could treat a just-expired token as still
  fresh. The condition now compares the numeric epoch-second `ttl` attribute
  (`#ttl > :nowEpoch`). The authoritative expiry check in `RefreshTokenService`
  was already correct, so the exposure was limited to a sub-second
  fail-open in the database-level backstop for the rotate TOCTOU window.
- **Stateful JWT validation rejects `jti`-less tokens instead of skipping
  revocation.** When a non-noop `AccessTokenStore` is bound,
  `PkAuthJwtValidator` previously guarded the store lookup with `jti != null`,
  so a validly-signed, in-issuer, in-audience, unexpired token carrying no
  `jti` bypassed the `exists` revocation gate entirely. The validator now
  returns `MissingClaim("jti")` for a `jti`-less token in stateful mode. Tokens
  minted by `PkAuthJwtIssuer` always carry a `jti`, so this never affected the
  library's own tokens; it closes the gap for any other token signed with the
  same keyset.
- **Corrected the `MagicLinkService.startLogin` timing-side-channel
  contract (documentation).** The javadoc claimed the method defeats timing
  side-channels, but the not-found path returns before JWT issuance and email
  dispatch, so response latency still distinguishes known from unknown
  usernames. The contract now documents the result-shape guarantee only and
  points hosts at uniform-latency / rate-limiting mitigations. No behavioural
  change.

## [1.1.0] — 2026-05-18

### Added

- `TokenTtlPolicy` SPI in `pk-auth-jwt` for per-audience JWT access-token TTL
  dispatch. Multi-client deployments (e.g. web vs cli vs mobile) can now
  configure different token lifetimes per audience without writing a custom
  issuer. Static factories `TokenTtlPolicy.fixed(default, overrides)` and
  `TokenTtlPolicy.single(ttl)` cover the common cases; implementations can also
  declare their `knownAudiences()` so the validator accepts the expanded
  audience set automatically. See ADR 0014.
- `JwtClaims` gains an optional `audience` field. When the issuer is called
  with a claims object whose `audience` is null, the JWT's `aud` claim falls
  back to `JwtConfig.defaultAudience()`. New convenience factory
  `JwtClaims.forPasskey(userHandle, credentialId, audience, amr)` etc. mirror
  the existing audience-less factories.
- `AccessTokenStore` SPI in `pk-auth-jwt` for stateful (server-revocable) access
  tokens. `PkAuthJwtIssuer` calls `record` on every issue; `PkAuthJwtValidator`
  calls `exists` on every validate. The default `AccessTokenStore.noop()` keeps
  stateless behaviour; hosts wire a real store (JDBI, DynamoDB) to opt in. See
  ADR 0015.
- `pk-auth-refresh-tokens` (new module): `RefreshTokenService` with `issue`,
  `rotate`, `revokeFamily`, `revokeAllForUser`, `listForUser`. Sealed
  `RotateResult` (Success / Replayed / Expired / Unknown / Revoked). Wire
  format `{refreshId}.{secret}` (both halves base64url); SHA-256
  hash-at-rest; hash-before-mark-used invariant. Family-based replay
  defense — re-presenting a used token scorches the entire family. See
  ADR 0013.
- `RefreshTokenRepository` SPI with the load-bearing `rotateAtomically`
  primitive: parent mark-used and successor insert commit atomically on
  every backend (JDBI transaction, DynamoDB `TransactWriteItems`,
  in-memory `ConcurrentHashMap.compute`).
- `pk-auth-persistence-jdbi`: `JdbiRefreshTokenRepository` + Flyway V9
  migration. PkAuthJdbiSchema.CURRENT_SCHEMA_VERSION → "9".
- `pk-auth-persistence-dynamodb`: `DynamoDbRefreshTokenRepository` with
  three-item layout (primary jti / user-index / family-index) and
  DynamoDB-native TTL.
- `pk-auth-testkit`: `InMemoryRefreshTokenRepository` +
  `RefreshTokenScenarios` parity test class — nine scenarios including
  the non-negotiable `concurrentRotationExactlyOneSucceedsFamilyRevoked`
  race test, driven by 8 threads + `CountDownLatch`, passing against
  in-memory, real Postgres, and DynamoDB Local.
- `RefreshHandler` (framework-neutral HTTP composer) + `PkAuthRefreshController`
  / `PkAuthRefreshResource` in Spring, Dropwizard, Micronaut adapters.
  `POST /auth/refresh` returns the new refresh + access JWT on success,
  401 with a typed `detail` on any failure.
- `AuthMethod.REFRESH` for access tokens minted from a refresh rotation.
- `JwtClaims.forRefresh(userHandle, audience, amr)` factory.
- Browser SDK: `PkAuthClient.refresh(wireToken)` returning a typed
  `RefreshResult` sum (`RefreshSuccess | RefreshFailure`) — never throws
  on 401.
- `RefreshTokenServiceDeletionListener` plugged into `UserDeletionService`
  so user-delete revokes every active refresh family alongside access
  tokens / credentials / backup codes / OTPs.
- `pk-auth-persistence-jdbi`: `JdbiAccessTokenStore` backed by the new
  `access_tokens` table (Flyway V8).
- `pk-auth-persistence-dynamodb`: `DynamoDbAccessTokenStore` using two items
  per JTI (primary jti-keyed item + user-indexed pointer item) with DynamoDB
  native TTL on the `ttl` attribute for asynchronous expiry cleanup.
- `pk-auth-testkit`: `InMemoryAccessTokenStore` + `AccessTokenStoreScenarios`
  parity-test class driven from in-memory / JDBI / DynamoDB integration tests.
- `UserDeletionService` and `UserDeletionListener` SPI in
  `pk-auth-core` (`com.codeheadsystems.pkauth.lifecycle`). Single fan-out
  point that runs every registered listener for a user, with idempotent +
  best-effort semantics and structured `pkauth.user.deletion` logging. See
  ADR 0016. The library ships listeners for credentials, backup codes, OTPs,
  and access tokens; each adapter wires them automatically.
- `CredentialRepository.deleteByUserHandle(UserHandle)` and
  `OtpRepository.deleteByUserHandle(UserHandle)` SPI methods for the fan-out.
  Implemented in all three persistence variants.

### Changed

- **Breaking.** `JwtConfig.tokenTtl: Duration` replaced by
  `JwtConfig.ttlPolicy: TokenTtlPolicy`. Pre-1.1 code that constructed
  `JwtConfig` directly must wrap the existing TTL in `TokenTtlPolicy.single(ttl)`.
  The `JwtConfig.defaults(issuer, audience)` factory still works as before and
  produces a single-TTL policy.
- **Breaking.** `JwtConfig.audience` renamed to `JwtConfig.defaultAudience`.
  The accessor moves from `config.audience()` to `config.defaultAudience()`.
  Semantic note: the validator now accepts any audience listed in
  `defaultAudience ∪ ttlPolicy.knownAudiences()`, which matters when running
  multiple client audiences through a single validator.
- **Breaking (adapters).** `PkAuthProperties.Jwt` (Spring),
  `PkAuthConfig.Jwt` (Dropwizard), and `PkAuthConfiguration.Jwt` (Micronaut)
  each gain a `ttlsByAudience: Map<String, Duration>` field and rename their
  single-TTL field; see each adapter's javadoc for the bound property name.
- **Breaking (SPI).** `CredentialRepository` and `OtpRepository` gain a
  `deleteByUserHandle(UserHandle) -> int` method. All shipped implementations
  (in-memory, JDBI, DynamoDB) updated. Downstream host-supplied
  implementations must add it; the natural impl is a single bulk-delete
  statement keyed on the user-handle column.
- `PkAuthJwtIssuer` and `PkAuthJwtValidator` gain new constructors that accept
  an `AccessTokenStore`. The legacy three-arg constructors remain and default
  to `AccessTokenStore.noop()`.
- Flyway schema version bumped to V9 (V8 access tokens + V9 refresh tokens).
  `PkAuthJdbiSchema.CURRENT_SCHEMA_VERSION` is now `"9"`.

## [1.0.0] — 2026-05 (stabilisation cut)

First stable release. Captures the surface produced by the 0.x development
series; see `git log` for the full history.

[Unreleased]: https://github.com/codeheadsystems/pk-auth/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/codeheadsystems/pk-auth/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/codeheadsystems/pk-auth/compare/v1.3.1...v2.0.0
[1.3.1]: https://github.com/codeheadsystems/pk-auth/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/codeheadsystems/pk-auth/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/codeheadsystems/pk-auth/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/codeheadsystems/pk-auth/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/codeheadsystems/pk-auth/releases/tag/v1.0.0
