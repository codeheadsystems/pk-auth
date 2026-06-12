# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

pk-auth is a **passkeys-first authentication library set for the JVM**, published to Maven Central under `com.codeheadsystems`. All modules share one version (`gradle.properties` → currently `1.3.1-SNAPSHOT`). It is *not* an identity provider: it owns passkeys/credentials, never users — the host maps users via the `UserLookup` SPI.

The canonical architecture reference is [`DESIGN.md`](./DESIGN.md); per-decision rationale lives in [`docs/adr/`](./docs/adr/) (Nygard format, numbered). Read the relevant ADR before changing cross-module behavior.

## Build & test

JDK 21 is required (Gradle's toolchain fetches one if absent). Node ≥ 20 + npm are needed for the browser SDK, which Gradle drives automatically.

```sh
./gradlew check                          # full gate: spotlessCheck + test + jacoco coverage verify
./gradlew clean build test               # aggregate test across all subprojects
./gradlew :pk-auth-core:test             # one module's tests
./gradlew :pk-auth-jwt:test --tests "com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuerTest"   # one test class
./gradlew :pk-auth-core:test --tests "*.SomeTest.someMethod"                                # one test method
./gradlew spotlessApply                  # auto-fix formatting (google-java-format, SPDX header, imports)
./gradlew :examples:spring-boot-demo:run # runnable demo at http://localhost:8080 (also dropwizard-demo / micronaut-demo — one at a time, all bind 8080)
```

- **Integration tests are ordinary `test` tasks** — the JDBI/DynamoDB persistence modules use Testcontainers (Postgres / DynamoDB Local), so `./gradlew :pk-auth-persistence-jdbi:test` needs **Docker** running. There is no separate `integrationTest` task or JUnit tag.
- Playwright end-to-end suites live under the `examples/` demos and need **Chrome** (drives a CDP virtual WebAuthn authenticator).
- The Gradle **build cache is disabled** on purpose (Spotless 8.x classloader bug) — see the comment in `gradle.properties`. Don't re-enable it.

## Architecture: three concentric rings

Dependency arrows always point **inward**. Adapters depend on core; core depends on no adapter, no framework, no servlet/HTTP API, no JDBC/DynamoDB.

1. **`pk-auth-core`** — framework- and persistence-neutral. Knows WebAuthn (WebAuthn4J), the wire contract, and declares the SPIs. `PasskeyAuthenticationService` is the ceremony entry point. The exported packages are `api`, `ceremony`, `config`, `credential`, `error`, `json`, `lifecycle`, `metrics`, and `spi` (enforced via `module-info.java`); everything else is module-internal.
2. **SPIs (ports)** — narrow interfaces the host implements: `UserLookup`, `CredentialRepository`, `ChallengeStore` (required); `BackupCodeRepository`, `OtpRepository`, `EmailSender`, `SmsSender`, `RefreshTokenRepository`, `AccessTokenStore`, `TokenTtlPolicy`, `UserDeletionListener`, `AttestationTrustPolicy`, `OriginValidator`, `ClockProvider` (optional / feature-gated). See `DESIGN.md` §6 for the required-vs-optional table.
3. **Adapters** — `pk-auth-spring-boot-starter` (Spring Boot 4 / Security 7 autoconfigure), `pk-auth-dropwizard` (Dropwizard 5 `ConfiguredBundle` + Dagger 2), `pk-auth-micronaut` (Micronaut 4 `@Factory` + `@Filter`, deliberately **not** Micronaut Security). Each mounts the same `/auth/**` JSON contract and pattern-matches the core's sealed result sums into HTTP status codes.

Feature modules (`pk-auth-backup-codes`, `pk-auth-magic-link`, `pk-auth-otp`, `pk-auth-refresh-tokens`) and persistence modules (`pk-auth-persistence-jdbi`, `pk-auth-persistence-dynamodb`, in-memory `pk-auth-testkit`) implement core-declared SPIs and are wired in by the host.

### Things that bite if you don't know them

- **Sealed result sums, not exceptions.** Ceremony and admin operations return sealed interfaces — `AdminResult<T>` (`Success | NotFound | Forbidden | ValidationFailed | Conflict | RateLimited`), `RegistrationResult`, `AssertionResult`, `RotateResult`, `JwtVerificationResult`. Adapters map these to HTTP; never throw across that boundary. When you add a variant, every adapter's `*ResultMapper` must handle it.
- **Wire bytes are base64url, no padding** (RFC 4648 §5). Jackson 3 adapters get this from `PkAuthObjectMappers.pkAuthModule()`; the Dropwizard adapter is still on Jackson 2 and uses the `PkAuthJacksonBridge`.
- **`finish` endpoints are not idempotent** — challenges are single-use via `ChallengeStore.takeOnce`. There is **no shared transaction across SPIs**: `takeOnce` is consumed before `CredentialRepository.save`; a failed save forces a ceremony restart. This is intentional — see [`docs/transactional-semantics.md`](./docs/transactional-semantics.md).
- **All three adapters mount identical `/auth/**` paths** (`/auth/passkeys/**`, `/auth/refresh`, `/auth/admin/**`) — Dropwizard's Jersey resources use the same `@Path("/auth/passkeys")` etc. as Spring/Micronaut, so the TS SDK targets one path scheme everywhere (no per-client path override).
- **DI annotations differ by adapter on purpose** (`CONTRIBUTING.md` §9): Spring and Micronaut auto-detect the single constructor — do **not** add `@Autowired`/`@Inject`. Dropwizard's Dagger 2 wiring **requires** `@Inject` on the injected constructor. Match the module you're in.
- **Atomic-claim operations return `boolean`** so the caller can detect a race-lost claim — JDBI uses conditional `UPDATE ... WHERE consumed_at IS NULL`; DynamoDB uses `ConditionExpression` (failed condition → `ConditionalCheckFailedException` mapped to `Conflict`/`Expired`).
- **DynamoDB is single-table** (`DynamoDbTable<T>` per item type; refresh tokens write 3 items per token for the jti/user/family indexes). **JDBI uses Flyway** migrations at `pk-auth-persistence-jdbi/src/main/resources/db/migration/` — bump `PkAuthJdbiSchema.CURRENT_SCHEMA_VERSION` when adding one.

## Conventions (enforced — `./gradlew check` fails otherwise)

- **SPDX header** `// SPDX-License-Identifier: MIT` on every Java file (Spotless adds/checks it).
- **`@since X.Y.Z`** Javadoc on every new/modified public API element across the library modules (the in-flight target is the active version in `gradle.properties` with the `-SNAPSHOT` suffix dropped — always check `gradle.properties` rather than trusting a hardcoded number here). Full policy in `CONTRIBUTING.md` §7.
- **JSpecify null discipline** — `@NonNull`/`@Nullable` on every public param and return; Error Prone enforces it. Compilation runs `-Xlint:all` with strict Error Prone.
- **Records for DTOs/configs/result variants; sealed interfaces for closed sums.** Public API sealed via `module-info.java` exports.
- **Conventional commits** (`feat(core):`, `fix(jdbi):`, `docs(adr):`, `build:`, `ci:`). Small, atomic.
- **New dependencies go through `gradle/libs.versions.toml`** (the version catalog) and are justified in the commit/ADR. Build conventions live in `build-logic/` (`pkauth.java-conventions`, `library-conventions`, `test-conventions`, `publish-conventions`), applied per-module.
- **No `TODO` in main** without a linked GitHub issue.
- **Non-trivial cross-module decisions get an ADR** under `docs/adr/`, numbered sequentially.
- JaCoCo gate: ≥ 80% line coverage on `pk-auth-core`, ≥ 70% on adapters (wired per-module via `JacocoCoverageVerification`).

## Browser SDK

`clients/passkeys-browser/` is a zero-dep TypeScript SDK (`@pk-auth/passkeys-browser`, ESM + CJS, vitest-tested). Its `dist/` is **gitignored** — Gradle's `:buildPasskeysBrowserSdk` runs `npm ci && npm run build` (tsup) and the demos' `processResources` copy the output in. The Gradle build is the source of truth; don't commit built bundles.
