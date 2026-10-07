# CLAUDE.md

## Project summary

pk-auth is a passkeys-first authentication library set for the JVM, published to Maven Central
under `com.codeheadsystems`. All modules share one version (the `version` in `gradle.properties` is
authoritative). It is not an identity provider: it owns passkeys and credentials, never users, and
the host maps users via the `UserLookup` SPI.

The canonical architecture reference is [`DESIGN.md`](./DESIGN.md); per-decision rationale lives in
[`docs/adr/`](./docs/adr/) (Nygard format, numbered). The relevant ADR must be read before
cross-module behaviour changes.

## Build and test

JDK 21 is required (Gradle's toolchain fetches one if absent). Node ≥ 22.22.2 and npm are needed
for the browser SDK, which Gradle drives automatically.

```sh
./gradlew check                          # full gate: spotlessCheck + test + jacoco coverage verify
./gradlew clean build test               # aggregate test across all subprojects
./gradlew :pk-auth-core:test             # one module's tests
./gradlew :pk-auth-jwt:test --tests "com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuerTest"   # one test class
./gradlew :pk-auth-core:test --tests "*.SomeTest.someMethod"                                # one test method
./gradlew spotlessApply                  # auto-fix formatting (google-java-format, SPDX header, imports)
./gradlew :examples:spring-boot-demo:run # runnable demo at http://localhost:8080 (also dropwizard-demo / micronaut-demo — one at a time, all bind 8080)
```

- Integration tests are ordinary `test` tasks. The JDBI and DynamoDB persistence modules use
  Testcontainers (Postgres / DynamoDB Local), so `./gradlew :pk-auth-persistence-jdbi:test` needs
  Docker running. There is no separate `integrationTest` task or JUnit tag.
- Playwright end-to-end suites live under the `examples/` demos and need Chrome (drives a CDP
  virtual WebAuthn authenticator). They are wired into each demo's `check` via the `e2eTest` task
  (`pkauth.e2e-conventions`) but are opt-in: they run only when `PK_RUN_E2E=1` (or `-PrunE2e`) is
  set, so a default `./gradlew check` and the CI `build` job stay fast and Chrome-free. One suite
  runs with `PK_RUN_E2E=1 ./gradlew :examples:spring-boot-demo:e2eTest`; the task itself does
  `npm ci` + `npx playwright install chrome` and boots the demo via its Gradle `run` task. CI runs
  all three in the `e2e` matrix job (`.github/workflows/ci.yml`, with `PW_INSTALL_DEPS=1` so
  Chrome's OS deps are installed too).
- The Gradle build cache is disabled because of a Spotless 8.x classloader bug; see the comment in
  `gradle.properties`. It must not be re-enabled.

## Architecture: three concentric rings

Dependency arrows point inward. Adapters depend on core; core depends on no adapter, no framework,
no servlet/HTTP API, and no JDBC/DynamoDB.

1. `pk-auth-core` is framework- and persistence-neutral. It knows WebAuthn (WebAuthn4J), the wire
   contract, and declares the SPIs. `PasskeyAuthenticationService` is the ceremony entry point. The
   exported packages are `api`, `ceremony`, `config`, `credential`, `error`, `json`, `lifecycle`,
   `metrics`, `ratelimit`, and `spi` (enforced via `module-info.java`); everything else is
   module-internal.
2. SPIs (ports) are narrow interfaces the host implements. `UserLookup`, `CredentialRepository`,
   and `ChallengeStore` are required. `BackupCodeRepository`, `OtpRepository`, `EmailSender`,
   `SmsSender`, `RefreshTokenRepository`, `AccessTokenStore`, `TokenTtlPolicy`, `RevocationCheck`,
   `UserDeletionListener`, `AttestationTrustPolicy`, `OriginValidator`, `ClockProvider`,
   `ConsumedJtiStore`, `CeremonyRateLimiter`, and `MessageFormatter` are optional or
   feature-gated. `DESIGN.md` §6 holds the required-vs-optional table.
3. Adapters are `pk-auth-spring-boot-starter` (Spring Boot 4 / Security 7 autoconfigure),
   `pk-auth-dropwizard` (Dropwizard 5 `ConfiguredBundle` + Dagger 2), and `pk-auth-micronaut`
   (Micronaut 4 `@Factory` + `@Filter`; no Micronaut Security). Each mounts the same `/auth/**`
   JSON contract and pattern-matches the core's sealed result sums into HTTP status codes.

Feature modules (`pk-auth-backup-codes`, `pk-auth-magic-link`, `pk-auth-otp`,
`pk-auth-refresh-tokens`, `pk-auth-admin-api`) and persistence modules (`pk-auth-persistence-jdbi`,
`pk-auth-persistence-dynamodb`, in-memory `pk-auth-testkit`) implement core-declared SPIs and are
wired in by the host. `pk-auth-admin-api` hosts `AdminService` / `AdminResult<T>` and the
account/credential/backup-code/email/phone admin operations mounted by all three adapters at
`/auth/admin/**`.

### Known pitfalls

- Ceremony and admin operations return sealed result sums, not exceptions: `AdminResult<T>`
  (`Success | NotFound | Forbidden | ValidationFailed | Conflict | RateLimited`, declared in
  `pk-auth-admin-api`), `RegistrationResult`, `AssertionResult` (core), `RotateResult`
  (`pk-auth-refresh-tokens`), and `JwtVerificationResult` (`pk-auth-jwt`). Adapters map these to
  HTTP, and exceptions must not be thrown across that boundary. A new variant must be handled by
  every adapter's `*ResultMapper`.
- Wire bytes are base64url with no padding (RFC 4648 §5). Jackson 3 adapters (Spring) get this from
  `PkAuthObjectMappers.pkAuthModule()`. Dropwizard and Micronaut are still on Jackson 2 and use
  `PkAuthJacksonBridge` (Dropwizard) and the `PkAuthJacksonModule` bean (Micronaut).
- `finish` endpoints are not idempotent: challenges are single-use via `ChallengeStore.takeOnce`.
  There is no shared transaction across SPIs. `takeOnce` is consumed before
  `CredentialRepository.save`, and a failed save forces a ceremony restart. This is the specified
  behaviour; see [`docs/transactional-semantics.md`](./docs/transactional-semantics.md).
- All three adapters mount identical `/auth/**` paths (`/auth/passkeys/**`, `/auth/refresh`,
  `/auth/admin/**`). Dropwizard's Jersey resources use the same `@Path("/auth/passkeys")` etc. as
  Spring and Micronaut, so the TS SDK targets one path scheme everywhere, with no per-client path
  override.
- DI annotations differ by adapter (`CONTRIBUTING.md` §9). Spring and Micronaut auto-detect the
  single constructor, so `@Autowired` and `@Inject` must not be added there. Dropwizard's Dagger 2
  wiring requires `@Inject` on the injected constructor. New code matches the module it lives in.
- Atomic-claim operations return `boolean` so that the caller can detect a race-lost claim. JDBI
  uses conditional `UPDATE ... WHERE consumed_at IS NULL`. DynamoDB uses `ConditionExpression` (a
  failed condition raises `ConditionalCheckFailedException`, mapped to `Conflict` / `Expired`).
- DynamoDB is single-table (`DynamoDbTable<T>` per item type; refresh tokens write 3 items per
  token for the jti/user/family indexes). JDBI uses Flyway migrations at
  `pk-auth-persistence-jdbi/src/main/resources/db/migration/`, and adding one requires bumping
  `PkAuthJdbiSchema.CURRENT_SCHEMA_VERSION`.

## Enforced conventions

`./gradlew check` fails when any of the following is violated.

- SPDX header `// SPDX-License-Identifier: MIT` on every Java file (Spotless adds and checks it).
- `@since X.Y.Z` Javadoc on every new or modified public API element across the library modules.
  The in-flight target is the active version in `gradle.properties` with the `-SNAPSHOT` suffix
  dropped. `gradle.properties` is always read at the time of the change, and no hardcoded number in
  a document is trusted. Full policy in `CONTRIBUTING.md` §7.
- JSpecify null discipline: `@NonNull` / `@Nullable` on every public parameter and return. Error
  Prone enforces it. Compilation runs `-Xlint:all` with strict Error Prone.
- Records for DTOs, configs, and result variants; sealed interfaces for closed sums. Public API is
  sealed via `module-info.java` exports.
- Conventional commits (`feat(core):`, `fix(jdbi):`, `docs(adr):`, `build:`, `ci:`), small and
  atomic.
- New dependencies go through `gradle/libs.versions.toml` (the version catalog) and are justified
  in the commit or ADR. Build conventions live in `build-logic/` (`pkauth.java-conventions`,
  `library-conventions`, `test-conventions`, `publish-conventions`), applied per module.
- No `TODO` in main without a linked GitHub issue.
- Non-trivial cross-module decisions get an ADR under `docs/adr/`, numbered sequentially.
- Documentation follows [`docs/style.md`](./docs/style.md): register, emphasis, headings,
  punctuation (no em dashes, serial comma, British spelling, 100-column wrap) and terminology. It
  applies to every Markdown file, Javadoc, and the `site/`, and it must be read before any of them
  is written or edited.
- JaCoCo gate: `pkauth.test-conventions` sets a LINE ≥ 70% / BRANCH ≥ 55% floor on every library
  module (including the adapters). Modules raise it in their own `build.gradle.kts`: LINE ≥ 80% on
  `pk-auth-core`, `pk-auth-admin-api`, `pk-auth-jwt`; BRANCH ≥ 85% on `pk-auth-jwt`,
  `pk-auth-backup-codes`; BRANCH ≥ 80% on `pk-auth-otp`, `pk-auth-refresh-tokens`.

## Browser SDK

`clients/passkeys-browser/` is a zero-dependency TypeScript SDK (`@pk-auth/passkeys-browser`, ESM +
CJS, vitest-tested). Its `dist/` is gitignored. Gradle's `:buildPasskeysBrowserSdk` runs
`npm ci && npm run build` (tsup), and the demos' `processResources` copy the output in. The Gradle
build is the source of truth, and built bundles must not be committed.
