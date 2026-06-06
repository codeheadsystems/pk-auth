# Changelog

All notable changes to pk-auth are recorded here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The 0.x line is treated as a single pre-stable development series — see
`docs/stability.md` and the early ADRs for context. This changelog starts at the
1.0.0 stabilisation cut; for 0.x history consult `git log` against the relevant
tags.

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

[Unreleased]: https://github.com/codeheadsystems/pk-auth/compare/v1.3.1...HEAD
[1.3.1]: https://github.com/codeheadsystems/pk-auth/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/codeheadsystems/pk-auth/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/codeheadsystems/pk-auth/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/codeheadsystems/pk-auth/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/codeheadsystems/pk-auth/releases/tag/v1.0.0
