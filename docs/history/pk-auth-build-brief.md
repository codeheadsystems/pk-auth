> **Historical document.** This is the original bootstrap prompt used to scaffold pk-auth
> before 1.0. It is no longer maintained and is **not** authoritative: the current architecture is
> described in [`DESIGN.md`](../../DESIGN.md), and per-decision rationale lives in
> [`docs/adr/`](../adr/). Where this brief and those documents disagree, they win. Section and
> phase numbers below are kept only so older ADRs and comments that cite them still resolve.

# pk-auth — Build Brief for Claude Code

> Paste this file at the root of an empty `pk-auth` repository and ask Claude Code to execute it phase by phase. Treat this document as the source of truth for architectural decisions; if you encounter a genuinely ambiguous choice not covered here, **stop and ask the human** rather than guess.

---

## 1. Mission

Build a production-grade, **passkeys-first** authentication template for the JVM that ships as a reusable library set across **Spring Boot**, **Dropwizard**, and **Micronaut**. The codebase is meant to be copied or depended on by future projects, so prioritize:

1. Clean, framework-neutral abstractions in the core.
2. Feature parity across all three framework adapters.
3. Thorough tests and excellent documentation.
4. Operability (metrics, structured logs, sane defaults).

Volume of optional features is explicitly **not** a priority. Ship a small, sharp, well-tested core.

---

## 2. Repository Metadata

| | |
|---|---|
| **Root project** | `pk-auth` |
| **Group ID** | `com.codeheadsystems` |
| **Base package** | `com.codeheadsystems.pkauth` |
| **License** | MIT. Include a `LICENSE` file at root and an SPDX header (`// SPDX-License-Identifier: MIT`) at the top of every source file. |
| **JDK** | Java 21 (Gradle toolchain enforced). |
| **CI** | GitHub Actions. |
| **Hosting** | GitHub (assume public). |

---

## 3. Non-Negotiable Tech Choices

- **WebAuthn library**: `com.webauthn4j:webauthn4j-core` (latest stable — currently 0.31.x). Do **not** use `webauthn4j-spring-security`, and do **not** use Yubico's `java-webauthn-server`. The core wraps WebAuthn4J's `WebAuthnManager` directly.
- **Build**: Gradle with **Kotlin DSL**, version catalog at `gradle/libs.versions.toml`, convention plugins in an included build at `build-logic/` (not `buildSrc/`).
- **JSON**: Jackson 3 (`tools.jackson.core:jackson-databind`). Configure a shared `ObjectMapper` factory in the core (`pk-auth-core`) using the Jackson 3 `JsonMapper.builder()` flow, fail-on-unknown-properties on input, exclude nulls on output. Java time and JDK 8 datatype support is built into Jackson 3 databind — no separate `JavaTimeModule`/`Jdk8Module` modules needed. Annotations stay on `com.fasterxml.jackson.core:jackson-annotations 2.21` (works with both Jackson 2 and 3). The Dropwizard adapter still uses Jackson 2 internally (via `PkAuthJacksonBridge`) because Dropwizard 5.x ships its own Jackson 2 `ObjectMapper`. See ADR 0009.
- **JWT**: Nimbus JOSE+JWT (`com.nimbusds:nimbus-jose-jwt`). HS256 and ES256 supported; ES256 default for production.
- **SQL persistence**: **JDBI 3** + **Flyway** against PostgreSQL. **No Hibernate, no JPA, no Spring Data JPA, no Micronaut Data JPA.** A future JPA module may be added; do not add it now.
- **NoSQL persistence**: AWS SDK v2 (`software.amazon.awssdk:dynamodb-enhanced`).
- **DI per framework**:
  - Spring Boot → Spring DI.
  - Micronaut → Micronaut DI.
  - Dropwizard → **Dagger 2** (compile-time, annotation-processed). Do not use Guice or HK2 except where Jersey itself requires HK2 wiring under the hood.
- **Testing**: JUnit 5 (Jupiter), AssertJ, Mockito, Testcontainers (PostgreSQL **latest stable**, LocalStack for DynamoDB or `amazon/dynamodb-local` — pick whichever is faster on a cold CI run and document the choice in an ADR), Playwright for browser E2E.
- **Code quality**: Spotless with Google Java Format, Error Prone, JaCoCo with a coverage gate (≥80% line coverage on `pk-auth-core`; ≥70% on adapter modules).
- **Email/SMS**: SPIs only in the platform. Provide a `LoggingEmailSender` and `LoggingSmsSender` for dev; sketch (skeleton + interface, no live integration) a `JavaMailEmailSender` and a `TwilioSmsSender`. Do not pull in Twilio or SendGrid as required dependencies.

---

## 4. Architectural Stance

### 4.1 Ports & adapters / hexagonal
`pk-auth-core` knows nothing about Spring, Dropwizard, Micronaut, JDBC, DynamoDB, HTTP, or any servlet API. It exposes **SPIs (ports)** and **services**. Every framework, persistence, and transport concern lives in an adapter module.

### 4.2 Cross-framework neutral authentication
We deliberately **do not** use Spring Security's built-in `spring-security-webauthn` module. Instead, the core exposes a `PasskeyAuthenticationService` that each framework adapter wraps in its own idiom:

- Spring Boot → a custom `AuthenticationProvider` (`org.springframework.security.authentication.AuthenticationProvider`) + a `Filter` that delegates to the core.
- Dropwizard → a Jersey `Authenticator<PasskeyCredentials, PasskeyPrincipal>` + an `AuthDynamicFeature`.
- Micronaut → a plain `@Filter` (no Micronaut Security dependency).

This guarantees feature parity. Spring users who *prefer* Spring Security's webauthn module can opt out and use that instead — document this in the Spring module README as an alternative path, but don't implement it.

### 4.3 User store ownership
pk-auth owns the **credential layer**: passkey credentials, backup codes, magic-link tokens, OTP codes, and WebAuthn user handles. pk-auth does **not** own the user table.

Host applications implement a `UserLookup` SPI (in `pk-auth-core`) to map user handles ↔ their own user representation. Reference implementations exist:

- `pk-auth-persistence-jdbi`: `JdbiUserLookup` reading from a `users` table (schema documented but considered the host app's, not pk-auth's — example schema lives in the demo app's Flyway migrations).
- `pk-auth-persistence-dynamodb`: `DynamoDbUserLookup` reading from a `Users` table.

### 4.4 Stateless by default
A successful passkey ceremony issues a signed JWT via `pk-auth-jwt`. No HTTP session is required. Adapters MAY bridge to framework-native sessions for users who want that, but the default is stateless JWT.

### 4.5 Multi-credential first-class
A user can have multiple passkeys (e.g., Yubikey + iCloud Keychain + Windows Hello). Credentials are:
- Labeled by the user at registration (e.g., "Work laptop").
- Listable, individually removable, and rotatable.
- Tagged with metadata: AAGUID, transports, backup-eligible flag, backup-state flag, created/last-used timestamps.

### 4.6 Recovery and alternative-flow modules
Each non-passkey flow is its **own module**, opt-in, with its own SPI. These are alternatives or supplements, not replacements for passkey auth:

- `pk-auth-backup-codes` — One-time use, Argon2id-hashed at rest, regenerable on demand. Used when no passkey is available.
- `pk-auth-magic-link` — Signed, single-use, short-TTL token delivered by email. Two use cases: (a) account email verification after registration, (b) login when no passkey is available on the current device.
- `pk-auth-otp` — Random 6-digit numeric code, short TTL, rate-limited, delivered by SMS. Used for **phone number verification**, not as a primary login factor.

### 4.7 Challenge & state storage
Pluggable `ChallengeStore` SPI from day one. Implementations:
- `InMemoryChallengeStore` (Caffeine-backed, default for dev/test).
- `JdbiChallengeStore` (Postgres).
- `DynamoDbChallengeStore` (DynamoDB with TTL).

Do **not** put challenges in HTTP session.

---

## 5. Module Layout

```
pk-auth/
├── build-logic/                         # included build, convention plugins
│   ├── settings.gradle.kts
│   └── src/main/kotlin/
│       ├── pkauth.java-conventions.gradle.kts
│       ├── pkauth.library-conventions.gradle.kts
│       ├── pkauth.publish-conventions.gradle.kts
│       └── pkauth.test-conventions.gradle.kts
├── gradle/libs.versions.toml
├── settings.gradle.kts
├── build.gradle.kts
├── LICENSE
├── README.md
├── CONTRIBUTING.md
├── docs/
│   ├── adr/                             # Architecture Decision Records
│   │   ├── 0001-record-architecture-decisions.md
│   │   ├── 0002-webauthn4j-over-yubico.md
│   │   ├── 0003-jdbi-over-jpa.md
│   │   ├── 0004-dagger-for-dropwizard.md
│   │   ├── 0005-stateless-jwt-default.md
│   │   ├── 0006-userlookup-spi-not-owned.md
│   │   ├── 0007-dynamodb-local-vs-localstack.md
│   │   └── 0008-dynamodb-single-table-design.md
│   ├── (see DESIGN.md at project root)
│   ├── threat-model.md
│   └── operator-guide.md
├── pk-auth-bom/                         # platform BOM for downstream consumers
├── pk-auth-core/                        # SPIs, RP operations, result types, DTOs
├── pk-auth-jwt/                         # JWT issuance + validation
├── pk-auth-backup-codes/                # backup codes module
├── pk-auth-magic-link/                  # email magic link module
├── pk-auth-otp/                         # SMS OTP module
├── pk-auth-persistence-jdbi/            # JDBI3 + Flyway + Postgres
├── pk-auth-persistence-dynamodb/        # AWS SDK v2 DynamoDB Enhanced
├── pk-auth-testkit/                     # fake authenticator, fixtures, helpers
├── pk-auth-admin-api/                   # credential & account management service + DTOs
├── pk-auth-spring-boot-starter/         # Spring Boot autoconfiguration adapter
├── pk-auth-dropwizard/                  # Dropwizard Bundle + Dagger
├── pk-auth-micronaut/                   # Micronaut module
├── clients/
│   └── passkeys-browser/                # TypeScript SDK consumed by all example apps
│       ├── package.json
│       ├── tsconfig.json
│       ├── src/
│       └── dist/
├── examples/
│   ├── spring-boot-demo/
│   ├── dropwizard-demo/
│   └── micronaut-demo/
└── .github/
    └── workflows/
        ├── ci.yml
        ├── release.yml
        └── conformance.yml
```

---

## 6. Module Briefs

### 6.1 `pk-auth-core`

The framework-neutral heart. Dependencies: WebAuthn4J, Jackson, slf4j, Caffeine, Micrometer (core, optional via `compileOnly`). **No other runtime dependencies.**

**Package layout:**
```
com.codeheadsystems.pkauth
├── api          # public DTOs (records), result types (sealed)
├── ceremony     # RP operations: registration + authentication ceremonies
├── credential   # CredentialRecord, CredentialMetadata
├── error        # exception hierarchy and error codes
├── spi          # ports (interfaces) implemented by adapters
│   ├── CredentialRepository
│   ├── UserLookup
│   ├── ChallengeStore
│   ├── ClockProvider
│   ├── OriginValidator
│   └── AttestationTrustPolicy
├── config       # RelyingPartyConfig, CeremonyConfig (records)
├── json         # ObjectMapper factory, custom (de)serializers for byte arrays / base64url
├── metrics      # Micrometer counters/timers (no-op if Micrometer absent)
└── internal     # package-private wiring
```

**Key types to produce (signatures, not bodies):**

```java
public sealed interface RegistrationResult {
    record Success(CredentialRecord credential, AuthenticatorData authenticatorData) implements RegistrationResult {}
    record InvalidChallenge(String detail) implements RegistrationResult {}
    record OriginMismatch(String expected, String actual) implements RegistrationResult {}
    record AttestationRejected(String reason) implements RegistrationResult {}
    record DuplicateCredential(byte[] credentialId) implements RegistrationResult {}
    record InvalidPayload(String detail) implements RegistrationResult {}
}

public sealed interface AssertionResult {
    record Success(UserHandle userHandle, byte[] credentialId, long signCount) implements AssertionResult {}
    record UnknownCredential(byte[] credentialId) implements AssertionResult {}
    record InvalidChallenge(String detail) implements AssertionResult {}
    record OriginMismatch(String expected, String actual) implements AssertionResult {}
    record CounterRegression(long stored, long received) implements AssertionResult {}
    record UserVerificationRequired() implements AssertionResult {}
    record InvalidSignature() implements AssertionResult {}
}

public interface PasskeyAuthenticationService {
    PublicKeyCredentialCreationOptionsJson startRegistration(StartRegistrationRequest req);
    RegistrationResult finishRegistration(FinishRegistrationRequest req);
    PublicKeyCredentialRequestOptionsJson startAuthentication(StartAuthenticationRequest req);
    AssertionResult finishAuthentication(FinishAuthenticationRequest req);
}

public interface CredentialRepository {
    void save(CredentialRecord record);
    Optional<CredentialRecord> findByCredentialId(byte[] credentialId);
    List<CredentialRecord> findByUserHandle(UserHandle userHandle);
    void updateSignCount(byte[] credentialId, long newCount, Instant lastUsedAt);
    void updateLabel(byte[] credentialId, String label);
    void delete(byte[] credentialId);
}

public interface UserLookup {
    Optional<UserHandle> findUserHandleByUsername(String username);
    Optional<UserView> findUserByHandle(UserHandle handle);
    UserHandle createOrGetUserHandle(String username); // for registration of new users
    record UserView(UserHandle handle, String username, String displayName, boolean emailVerified, boolean phoneVerified) {}
}

public interface ChallengeStore {
    void put(ChallengeId id, ChallengeRecord record, Duration ttl);
    Optional<ChallengeRecord> takeOnce(ChallengeId id); // single-use: removes on read
}
```

**DTOs**: All `*Json` types are records that match the WebAuthn JSON spec field-for-field. Use `byte[]` for binary fields and configure Jackson to (de)serialize them as base64url (no padding). The JSON contract is the wire contract — keep it stable.

### 6.2 `pk-auth-jwt`

Issuance and validation of pk-auth-issued JWTs. Depends on Nimbus JOSE+JWT and `pk-auth-core`.

- Supports HS256 (HMAC, dev) and ES256 (EC, production). Algorithm is configurable.
- Standard claims: `iss`, `sub` (user handle base64url), `aud`, `iat`, `nbf`, `exp`, `jti`. Custom claims: `pkauth.method` (`passkey` | `backup-code` | `magic-link`), `pkauth.cred` (credential id, when method=passkey), `pkauth.amr` (array, RFC 8176 compatible).
- Key rotation: support a `JWKSource` with multiple active keys, the newest signs.
- Validation is a separate class from issuance — adapters typically only need the validator.

### 6.3 `pk-auth-backup-codes`

- Generates N codes (default 10) at registration or on demand. Codes are 10-character alphanumeric, displayed once, never stored in plaintext.
- Stored as Argon2id hashes (use `de.mkammerer:argon2-jvm`).
- One-time use; verifying a code marks it consumed.
- SPI: `BackupCodeRepository` (impls in jdbi and dynamodb modules).
- Service: `BackupCodeService` with `generate(UserHandle)`, `verify(UserHandle, String)`, `remainingCount(UserHandle)`, `regenerateAll(UserHandle)`.

### 6.4 `pk-auth-magic-link`

- Signed, single-use token in the URL (`/auth/magic?t=...`). The token is a JWT signed by the JWT module's key set, with a `pkauth.purpose` claim distinguishing `email-verify` vs `login`.
- Default TTL: 15 minutes (configurable).
- SPI: `EmailSender` (with `LoggingEmailSender` and skeleton `JavaMailEmailSender`).
- Service: `MagicLinkService` with `sendVerificationEmail(UserHandle, String email)`, `sendLoginEmail(String username)`, `consume(String token)`.
- Rate limiting: at most N emails per (user, purpose) per hour, enforced in the service against the challenge store.

### 6.5 `pk-auth-otp`

- 6-digit numeric code, default TTL 5 minutes, max 5 verification attempts per code.
- Used for **phone verification** flows: `send(UserHandle, String phoneE164)`, `verify(UserHandle, String code)`.
- SPI: `SmsSender` (with `LoggingSmsSender` and skeleton `TwilioSmsSender`).
- SPI: `OtpRepository`.
- Rate limiting per (user, phone): at most 3 codes per 15 minutes.

### 6.6 `pk-auth-persistence-jdbi`

- JDBI 3 with the `kotlin` extension *not* needed — pure Java.
- Flyway migrations under `src/main/resources/db/migration/`:
  - `V1__credentials.sql`
  - `V2__challenges.sql`
  - `V3__backup_codes.sql`
  - `V4__otp_codes.sql`
  - `V5__example_users.sql` (the `users` table; documented as host-app schema, included for demo apps).
- Implements: `CredentialRepository`, `ChallengeStore`, `BackupCodeRepository`, `OtpRepository`, `UserLookup` (reference impl).
- All blob columns are `BYTEA`. Timestamps are `TIMESTAMPTZ`.
- Each repo class takes a `Jdbi` instance via constructor.

### 6.7 `pk-auth-persistence-dynamodb`

- AWS SDK v2, `DynamoDbEnhancedClient`.
- **Single-table design for all auth concerns.** Credentials, challenges, backup codes, and OTP codes share one table. Newcomers learning the codebase should use the JDBI module; this module is the production-throughput option for AWS-native deployments.
- **UserLookup is a separate table.** The `UserLookup` SPI's reference implementation reads from a dedicated `PkAuthUsers` table because (a) users are host-app data, not pk-auth data, and (b) keeping user lookup separate lets host apps swap in their own user store without touching the auth single-table.
- Provide a `DynamoDbSchemaBootstrapper` utility that creates the tables (and GSIs) if missing — useful for local dev and integration tests against LocalStack / dynamodb-local. Idempotent.
- Implements the same SPIs as the JDBI module.
- Write ADR 0008 documenting the single-table key design and the access patterns it supports.

#### 6.7.1 Single-table schema: `PkAuthCore`

| Attribute | Type | Notes |
|---|---|---|
| `pk` | String (HASH) | Partition key. See item-type table below. |
| `sk` | String (RANGE) | Sort key. See item-type table below. |
| `entityType` | String | Denormalized item-type tag: `Credential` \| `Challenge` \| `BackupCode` \| `OtpCode`. Useful for diagnostics and for future migrations. |
| `ttl` | Number | Unix-epoch-seconds; set on items that must auto-expire (challenges, OTP codes, optionally consumed backup codes). Bind to the DynamoDB Time-To-Live setting. |
| `gsi1pk` | String | GSI1 partition key. Populated only on items reachable via the global index (see below). |
| `gsi1sk` | String | GSI1 sort key. |
| (payload attributes) | varies | Item-specific fields, listed below. |

**Item shapes:**

| Item | `pk` | `sk` | GSI1 | Payload fields |
|---|---|---|---|---|
| Credential | `USER#{userHandle}` | `CRED#{credentialIdB64Url}` | `gsi1pk=CRED#{credentialIdB64Url}`, `gsi1sk=META` | `credentialId`, `publicKeyCose`, `signCount`, `label`, `aaguid`, `transports`, `backupEligible`, `backupState`, `createdAt`, `lastUsedAt` |
| Challenge | `CHAL#{challengeId}` | `META` | — | `challenge`, `purpose` (`REGISTRATION` \| `ASSERTION`), `userHandle` (nullable), `expiresAt`, `ttl` |
| BackupCode | `USER#{userHandle}` | `BACKUP#{codeId}` | — | `hashedCode` (Argon2id), `consumed`, `consumedAt`, `createdAt` |
| OtpCode | `USER#{userHandle}` | `OTP#{otpId}` | — | `hashedCode` (Argon2id), `phoneE164`, `attempts`, `consumed`, `expiresAt`, `ttl` |

**Global Secondary Index `gsi1-credential-by-id`:**
- Partition key: `gsi1pk`, Sort key: `gsi1sk`. Projection: ALL.
- Sole purpose: look up a credential by its `credentialId` during the assertion ceremony (we don't know the user handle yet). Only Credential items populate GSI1.

**Access patterns covered:**

1. Save / update credential — `PutItem` (or `UpdateItem` for sign-count bumps using `ConditionExpression` to guard against counter regression).
2. Find credential by `credentialId` — `Query` on `gsi1-credential-by-id`.
3. List a user's credentials — `Query` on main table, `pk = USER#{userHandle}` with `sk begins_with CRED#`.
4. Delete a credential — `DeleteItem` by `(pk, sk)`.
5. Put challenge — `PutItem` with `ttl`.
6. Take challenge (atomic single-use) — `DeleteItem` with `ReturnValues = ALL_OLD`; return the deleted item if present, else empty.
7. List a user's backup codes — `Query` on `pk = USER#{userHandle}` with `sk begins_with BACKUP#`.
8. Consume backup code — `UpdateItem` with `ConditionExpression` `consumed = false`.
9. Put OTP code — `PutItem` with `ttl`.
10. List a user's active OTP codes — `Query` on `pk = USER#{userHandle}` with `sk begins_with OTP#`, filter `consumed = false`.
11. Increment OTP attempts — `UpdateItem` with `ConditionExpression` on `attempts < maxAttempts`.

**Separate table `PkAuthUsers` (UserLookup reference impl):**

| Attribute | Type | Notes |
|---|---|---|
| `pk` | String (HASH) | `USER#{userHandle}` |
| `sk` | String (RANGE) | `META` (single-row-per-user, leaving room for future expansion) |
| `userHandle` | String | base64url, same value as in `pk` minus the `USER#` prefix |
| `username` | String | host-app login identifier |
| `displayName` | String | |
| `emailVerified` | Boolean | |
| `phoneVerified` | Boolean | |
| `gsi1pk` | String | `USERNAME#{usernameLowercase}` |
| `gsi1sk` | String | `META` |

GSI `gsi1-user-by-username` lets us resolve a username → user handle at login time.

**Mapping in Java:**
- Use `DynamoDbEnhancedClient` with `@DynamoDbBean` annotated POJOs for each item type. Because all auth items share the same table, define a separate Enhanced-client `TableSchema` per item-type and use a `DynamoDbTable<T>` per type pointing at the same physical table — the SDK supports this via `DynamoDbTable.create(table, schema)`.
- Provide a single `PkAuthCoreTable` value type that holds the table name and is bound from configuration.
- Encode all binary fields (challenge bytes, credential public-key bytes) as base64url strings, **not** binary attributes. Rationale: simpler to inspect in the console, simpler to migrate, and we already use base64url over the wire.

### 6.8 `pk-auth-testkit`

- `FakeAuthenticator` — an in-process authenticator. Generates EC P-256 key pairs, signs challenges correctly, returns valid `clientDataJSON` and `authenticatorData`. Used to drive registration and assertion ceremonies end-to-end in unit and integration tests **without a browser**.
- `PkAuthFixtures` — canned `CredentialRecord`s, `UserHandle`s, configs.
- `InMemoryEverything` — in-memory impls of all SPIs assembled for tests.
- Published as a test-jar from this module so downstream consumers (and our own example apps) can use it.

### 6.9 `pk-auth-admin-api`

Framework-neutral service + DTOs for the credential and account management operations that authenticated users (and host-app support staff, where applicable) need. Each framework adapter mounts these operations as HTTP endpoints; the contract (JSON shapes, paths) is standardized here so the TypeScript SDK can target all three.

**Dependencies**: `pk-auth-core`, `pk-auth-backup-codes`, `pk-auth-magic-link`, `pk-auth-otp`. No framework or HTTP dependencies.

**Service interface (illustrative — Claude Code may refine method signatures during implementation):**

```java
public interface AdminService {
    List<CredentialSummary> listCredentials(UserHandle user);
    CredentialSummary renameCredential(UserHandle user, byte[] credentialId, String newLabel);
    void deleteCredential(UserHandle user, byte[] credentialId);

    BackupCodesGenerated regenerateBackupCodes(UserHandle user); // plaintext returned ONCE
    int remainingBackupCodes(UserHandle user);

    void startEmailVerification(UserHandle user, String email);
    void completeEmailVerification(String magicLinkToken); // no user; token identifies

    OtpDispatchResult startPhoneVerification(UserHandle user, String phoneE164);
    PhoneVerificationResult completePhoneVerification(UserHandle user, String code);

    AccountSummary getAccount(UserHandle user);
}
```

**Endpoints standardized for adapters to mount** (all require an authenticated JWT unless noted):

| Method | Path | Purpose |
|---|---|---|
| GET | `/auth/admin/account` | Current user summary (handle, username, verified flags, credential count, remaining backup codes). |
| GET | `/auth/admin/credentials` | List passkeys with metadata (label, AAGUID, created, lastUsed, backup state). |
| PATCH | `/auth/admin/credentials/{credentialId}` | Rename label. Body: `{ "label": "..." }`. |
| DELETE | `/auth/admin/credentials/{credentialId}` | Remove a passkey. Rejects when it would leave the user with zero credentials *and* zero remaining backup codes (configurable safety check). |
| POST | `/auth/admin/backup-codes/regenerate` | Regenerate and return plaintext backup codes (one-time view). |
| GET | `/auth/admin/backup-codes/count` | Remaining unused backup code count. |
| POST | `/auth/admin/email/start-verification` | Send a magic link to the supplied email. Body: `{ "email": "..." }`. |
| POST | `/auth/admin/email/complete-verification` | **Unauthenticated.** Body: `{ "token": "..." }`. Marks the email as verified. |
| POST | `/auth/admin/phone/start-verification` | Send an OTP. Body: `{ "phone": "+15551234567" }`. |
| POST | `/auth/admin/phone/complete-verification` | Body: `{ "code": "123456" }`. Marks the phone as verified. |

**Authorization model:**
- All authenticated endpoints scope to the JWT's subject (user handle). A user can only act on their own credentials.
- The module exposes an `AdminAuthorizer` SPI that adapter modules may extend to support host-app admin/staff impersonation flows. Default implementation: subject-scoped only.

**Safety rules baked into the service:**
- Deleting the last credential when no backup codes remain is rejected with a typed result variant. Adapters surface this as HTTP 409 with a stable error code.
- Regenerating backup codes invalidates all existing unused codes atomically.
- Rate limiting on email and phone verification endpoints reuses the rate-limit logic from the magic-link and OTP modules.

**Result types**: every operation returns a sealed `AdminResult<T>` mirroring the pattern used in core (`Success(T)`, `NotFound`, `Forbidden`, `ValidationFailed(String)`, `Conflict(String)`, `RateLimited(Duration retryAfter)`). Adapters map these to HTTP status codes via a single shared `AdminResultMapper`.

### 6.10 `pk-auth-spring-boot-starter`

- Targets Spring Boot 4.x, Spring Security 7.x. Java 21.
- `@AutoConfiguration` class that wires:
  - `PasskeyAuthenticationService` (from core).
  - `PkAuthAuthenticationProvider implements org.springframework.security.authentication.AuthenticationProvider` — wraps the service.
  - `PkAuthAuthenticationFilter` — extends `OncePerRequestFilter`, mounted at `/auth/**` paths.
  - JWT validation filter that produces a `JwtAuthenticationToken`.
  - If `pk-auth-admin-api` is on the classpath, also wires `AdminController` (`@RestController`) mounted at `/auth/admin/**`, with method-security rules enforcing subject-scoping.
- Configuration properties under `pkauth.*` bound to a `@ConfigurationProperties("pkauth")` record.
- Provide `spring.factories` / `AutoConfiguration.imports` correctly.
- Explicitly disable Spring Security's own webauthn module if present on the classpath (log a warning and refuse to start if both are configured).

### 6.11 `pk-auth-dropwizard`

- Targets the **latest released Dropwizard** (currently 5.x — Jakarta EE 10, Jetty 12, Jersey 4). The adapter tracks upstream rather than pinning a major: the Dependabot config does not block Dropwizard majors, and when a new major surfaces it is treated as a deliberate framework refresh (the same pattern as the Spring Boot 4 / Spring Security 7 move). Jackson 2 is still in play here — Dropwizard ships its own Jackson 2 ObjectMapper on the 5.x line; `PkAuthJacksonBridge` keeps translating until a future Dropwizard major moves to Jackson 3. Java 21.
- `PkAuthBundle implements ConfiguredBundle<HasPkAuthConfig>` with an `initialize` and `run`.
- Dagger 2 wiring:
  - `@Module PkAuthModule` providing all core services.
  - `@Module PersistenceModule` (overridable; demo wires the JDBI module).
  - `@Component(modules = {...}) PkAuthComponent` with provision methods for the Jersey resources.
  - Annotation processing must be configured in the module's Gradle build (`annotationProcessor "com.google.dagger:dagger-compiler:..."`).
- Jersey resources at `/auth/**` registered by the bundle.
- `PasskeyAuthenticator implements Authenticator<PasskeyCredentials, PasskeyPrincipal>` + `AuthDynamicFeature` registered.
- JWT validation via a Jersey filter (`ContainerRequestFilter`).
- If `pk-auth-admin-api` is on the classpath, the bundle registers `AdminResource` (a Jersey `@Path("/auth/admin")` class) wired through Dagger, with the JWT filter enforcing authentication and an admin-specific filter enforcing subject-scoping.
- `HasPkAuthConfig` interface for the host app's `Configuration` class to implement.

### 6.12 `pk-auth-micronaut`

- Targets Micronaut 4.x. Java 21.
- `@Factory` class producing `PasskeyAuthenticationService` and all wired dependencies.
- `@Controller("/auth")` exposing the four ceremony endpoints.
- If `pk-auth-admin-api` is on the classpath, a `@Controller("/auth/admin")` is registered automatically, secured via `@Secured(SecurityRule.IS_AUTHENTICATED)` with subject-scoping enforced in a `@RequestFilter`.
- `PkAuthAuthenticationProvider` implementing Micronaut Security's `AuthenticationProvider`.
- `SecurityRule` for path-based rules.
- `@ConfigurationProperties("pkauth")` for typed config.
- Use Micronaut Test (`@MicronautTest`) for integration tests.

### 6.13 `clients/passkeys-browser` (TypeScript SDK)

- Tiny, zero-dependency TS module. Ships as ESM and CJS.
- Exports:
  - **Ceremonies**: `startRegistration({ apiBase, username, label })`, `finishRegistration(...)`, `startAuthentication(...)`, `finishAuthentication(...)`.
  - **Admin** (require an auth token): `listCredentials()`, `renameCredential(id, label)`, `removeCredential(id)`, `regenerateBackupCodes()`, `remainingBackupCodes()`, `startEmailVerification(email)`, `completeEmailVerification(token)`, `startPhoneVerification(phone)`, `completePhoneVerification(code)`, `getAccount()`.
- Handles base64url ↔ `ArrayBuffer` conversions for the WebAuthn API.
- Supports conditional UI (`mediation: 'conditional'`) opt-in.
- Token storage is the consumer's responsibility — the SDK accepts a `getToken: () => string | null` callback at construction.
- Built with `tsup` (or plain `tsc`), tested with `vitest`.
- Consumed by all three example apps via a relative path (no npm publish step required initially).

### 6.14 Example apps

Each demo app must:
- Run with `./gradlew :examples:<name>:run` (or `bootRun` for Spring).
- Use Postgres via Testcontainers in tests, and require a locally-running Postgres + DynamoDB Local in development (provide a `docker-compose.yml` per demo).
- Serve a single-page demo at `/` with: register account, register additional passkey, list passkeys (with rename/delete), login, generate backup codes (view-once), verify email via magic link, verify phone via OTP, view current account summary.
- Show JWT contents on the post-login page.
- Use the shared TS SDK from `clients/passkeys-browser` for both ceremony and admin operations.
- Two persistence variants: each demo ships with a `--persistence=jdbi` (default) and `--persistence=dynamodb` runtime flag so reviewers can exercise both backends without changing the codebase.

---

## 7. Security Requirements (apply everywhere)

- Origin validation is **strict** by default; allow-list configurable.
- Counter regression rejects by default; configurable to `warn` for sites that primarily expect synced (counter-0) passkeys.
- Challenge TTL: 5 minutes default, configurable. Single-use enforced atomically in `ChallengeStore.takeOnce`.
- Attestation policy: `none` by default (appropriate for consumer passkeys). Pluggable `AttestationTrustPolicy` for environments that need MDS3 / metadata-service validation — leave a hook, do not implement MDS3 fetch in v1.
- No raw credential public keys or `clientDataJSON` in logs. Ever. Use structured logging with explicit allow-listed fields.
- All inputs at API boundaries validated. Reject any payload exceeding 16 KB.
- Argon2id for backup codes; bcrypt or Argon2id for any password-shaped thing (we should have none, but if added later).
- Rate limits as specified in module briefs. Use the `ChallengeStore` (or a sibling `RateLimitStore`) for rate-limit counters; do not introduce a new infra dependency.
- JWT keys loadable from env vars, files, or AWS Secrets Manager (via an adapter — sketch only, not required).

---

## 8. Observability

- **Logging**: SLF4J + Logback. Structured (JSON) logs in production profile, pretty logs in dev profile. Every ceremony step logs with `eventId`, `userHandle` (base64url, never PII), `credentialIdHash` (sha-256 hex prefix), `outcome`, and `latencyMs`.
- **Metrics** (Micrometer): counters for each ceremony outcome (`pkauth.registration.outcome{result=...}`, `pkauth.assertion.outcome{result=...}`), timers for each ceremony, gauge for active challenges in store.
- **Tracing**: leave hooks. Micrometer Tracing optional via `compileOnly` in core; adapters wire it if present.

---

## 9. CI / Build / Release

### GitHub Actions workflows

- `ci.yml` (on push + PR): matrix over `ubuntu-latest` × Java 21. Steps: checkout, set up JDK, set up Gradle cache, run `./gradlew check`, upload JaCoCo report. Run Testcontainers tests (Docker is available on `ubuntu-latest`).
- `release.yml` (on tag `v*`): build all artifacts, sign with GPG, publish to Maven Central via the Gradle Publish Plugin, publish the BOM, generate a GitHub Release with auto-generated notes.
- `conformance.yml` (manual dispatch, nightly schedule): run the FIDO conformance test harness against the demo apps. Mark as "informational" — failures don't break main. (Stub this workflow with a TODO if the conformance tooling is too heavy to set up in phase 1; document in an ADR.)

### Build conventions (`build-logic/`)

- `pkauth.java-conventions.gradle.kts`: Java 21 toolchain, UTF-8, `-Xlint:all -Werror`, error-prone, Spotless.
- `pkauth.library-conventions.gradle.kts`: applies java conventions + `java-library` + publishing metadata.
- `pkauth.test-conventions.gradle.kts`: JUnit 5, AssertJ, Mockito; JaCoCo with coverage rules; Testcontainers reuse enabled.
- `pkauth.publish-conventions.gradle.kts`: `maven-publish`, POM metadata, signing config (gated by env).

### Versioning

- Single root version. SemVer. Pre-1.0 so breaking changes are expected. Start at `0.1.0-SNAPSHOT`.

---

## 10. Implementation Phases

Execute these in order. Each phase ends with a green `./gradlew check` and a working demo of what was built. **Do not start a phase before the previous one's tests pass.**

### Phase 0 — Repo scaffold
- Initialize Gradle multi-module project, version catalog, included build for convention plugins.
- Add `LICENSE` (MIT), `README.md` (skeleton), `CONTRIBUTING.md`, `.gitignore`, `.editorconfig`.
- Set up Spotless + error-prone + JaCoCo via convention plugins.
- Set up GitHub Actions `ci.yml` with a no-op build that passes.
- Write ADR 0001.
- **Acceptance**: `./gradlew build` succeeds on an empty project; CI is green.

### Phase 1 — `pk-auth-core` skeleton
- All SPIs, DTOs, result types, error hierarchy, config records.
- `PasskeyAuthenticationService` interface with no impl yet.
- `ObjectMapper` factory in `json` package, fully tested for byte-array ↔ base64url round-tripping.
- Write ADR 0002 (WebAuthn4J choice).
- **Acceptance**: All public types exist; the module compiles; >90% of types are covered by simple structural tests.

### Phase 2 — `pk-auth-core` ceremonies
- Implement `DefaultPasskeyAuthenticationService` using WebAuthn4J's `WebAuthnManager`.
- Map every WebAuthn4J exception to a `*Result` variant — no exceptions cross the service boundary except programmer errors.
- Wire `ChallengeStore` correctly (atomic single-use).
- **Acceptance**: Service is unit-testable with mocks; no framework dependencies present.

### Phase 3 — `pk-auth-testkit`
- Implement `FakeAuthenticator` (EC P-256, supports both registration and assertion).
- In-memory impls of all SPIs.
- **Acceptance**: From this module's own tests, drive a full registration → assertion ceremony against `DefaultPasskeyAuthenticationService` with no real browser.

### Phase 4 — `pk-auth-jwt`
- Issuer + validator, HS256 + ES256, key rotation support.
- **Acceptance**: Round-trip issue → validate works; rejected on tampered signature, expired, wrong audience, wrong issuer.

### Phase 5 — Persistence modules
- `pk-auth-persistence-jdbi` with Flyway migrations and Testcontainers-Postgres tests.
- `pk-auth-persistence-dynamodb` with single-table design (`PkAuthCore`) + separate `PkAuthUsers` for `UserLookup`. Tests via LocalStack or dynamodb-local.
- Both modules implement: `CredentialRepository`, `ChallengeStore`, `UserLookup`. (Backup-code and OTP repos arrive in Phase 6.)
- Write ADR 0003 (JDBI over JPA), ADR 0007 (DDB Local choice), and ADR 0008 (single-table key design).
- **Acceptance**: Same ceremony tests from Phase 3 pass against each persistence backend via parameterized tests.

### Phase 6 — Alternative-flow modules
- `pk-auth-backup-codes`, `pk-auth-magic-link`, `pk-auth-otp` in parallel.
- Extend JDBI and DynamoDB modules with the new repository impls. For DynamoDB, the new item types extend the existing `PkAuthCore` single-table — no new tables.
- **Acceptance**: Each module independently testable with the testkit; integration tests against both persistence backends pass.

### Phase 7 — `pk-auth-admin-api`
- `AdminService` interface and `DefaultAdminService` impl wiring credential, backup-code, magic-link, and OTP services.
- DTOs and sealed `AdminResult<T>` hierarchy.
- `AdminAuthorizer` SPI with default subject-scoped implementation.
- Unit tests against `InMemoryEverything` + integration tests against both JDBI and DynamoDB persistence.
- **Acceptance**: All admin operations covered by tests; safety rules (e.g., cannot delete last credential without backup codes) enforced.

### Phase 8 — Spring Boot starter + demo
- `pk-auth-spring-boot-starter` autoconfiguration, including conditional wiring of admin endpoints when `pk-auth-admin-api` is on the classpath.
- `examples/spring-boot-demo` exercising all flows: register, multi-passkey, login, list/rename/delete passkeys, backup codes, magic link, OTP phone verify, account summary.
- Demo runnable against both JDBI/Postgres and DynamoDB via runtime flag.
- Write ADR 0005 (stateless JWT).
- **Acceptance**: `./gradlew :examples:spring-boot-demo:bootRun` + manual browser walk-through works for both persistence variants. Integration tests using Spring's `MockMvc` + `FakeAuthenticator` pass.

### Phase 9 — Dropwizard adapter + demo
- `pk-auth-dropwizard` with Dagger wiring, including admin resource when `pk-auth-admin-api` is present.
- `examples/dropwizard-demo` exercising all flows for both persistence variants.
- Write ADR 0004 (Dagger for Dropwizard).
- **Acceptance**: same as phase 8 but for Dropwizard. Integration tests use `DropwizardAppExtension`.

### Phase 10 — Micronaut adapter + demo
- `pk-auth-micronaut` module with conditional admin controller.
- `examples/micronaut-demo` exercising all flows for both persistence variants.
- **Acceptance**: same as phase 8 but for Micronaut. `@MicronautTest` integration tests pass.

### Phase 11 — Frontend SDK
- `clients/passkeys-browser` TypeScript SDK covering both ceremony and admin operations, fully tested with vitest.
- Wire all three example apps to consume it.
- **Acceptance**: TS tests pass; all three demos render a working UI that drives the full feature set including the passkey-management page.

### Phase 12 — E2E + polish
- Playwright tests in each demo: register → login → manage passkeys (rename + delete) → backup codes (view + regenerate) → magic link → OTP. Use Chrome's virtual authenticator (CDP `WebAuthn.addVirtualAuthenticator`).
- Run each demo's E2E suite against both persistence variants in CI.
- README polish for every module.
- ADRs reviewed and complete.
- Operator guide and threat model written.
- **Acceptance**: `./gradlew check && (cd clients/passkeys-browser && npm test) && (cd examples/<each> && npx playwright test)` all green for both persistence variants.

---

## 11. Quality Bar

- **Tests**: every public type in core has tests. Every adapter has both unit tests (mocked SPIs) and integration tests (real Testcontainers backend + `FakeAuthenticator`).
- **Coverage**: ≥80% line on `pk-auth-core`, ≥70% on adapters. Enforced via JaCoCo verification rules in convention plugins.
- **Docs**: every module has a README explaining purpose, public API, and a "5-minute integration" snippet. Root README explains the architecture, has a diagram (Mermaid), and links to ADRs.
- **No `TODO`** in main branch unless paired with a GitHub issue link.
- **Public API is sealed**: `module-info.java` files in every module exporting only `api`, `spi`, and `config` packages. Internal packages are not exported.
- **Null discipline**: `@org.jspecify.annotations.NonNull` / `@Nullable` on every public method parameter and return type.
- **Records over classes** for DTOs, configs, and result variants. Sealed interfaces for closed sums.
- **No reflection in hot paths**. The only reflection is Jackson's, and it's confined to (de)serialization boundaries.
- **Virtual threads** enabled in every adapter's HTTP server config (Tomcat in Spring Boot, Jetty in Dropwizard, Netty in Micronaut). Document this in each adapter's README.

---

## 12. Working Agreements with Claude Code

1. **Phase discipline**: complete phase N's acceptance criteria before starting phase N+1. Run `./gradlew check` between phases and commit.
2. **Ask, don't guess**: if a design decision is not covered in this brief and is non-trivial, stop and ask the human. Acceptable "minor" decisions to make autonomously: method names, internal package layout, test data values, log message wording. Anything that touches public API, dependency selection, persistence schema, security posture, or cross-module contracts: ask.
3. **Commits**: small, atomic, conventional-commits style (`feat(core): ...`, `test(jdbi): ...`, `docs(adr): ...`).
4. **Branching**: work on `main` with frequent commits is fine for the bootstrap; once a v0.1.0 is tagged, switch to feature branches.
5. **Don't add dependencies casually**. Every new library goes through the version catalog and is justified in a commit message or ADR.
6. **Don't optimize prematurely**. Make it correct, make it tested, then make it fast.
7. **Don't write production-quality email/SMS senders**. The skeletons are intentional; this is auth-layer infrastructure, not a messaging platform.

---

## 13. Out of Scope (Explicit)

These are deliberately excluded from v0.x. Do not add them without consultation:

- JPA / Hibernate / Spring Data JPA / Micronaut Data JPA persistence module.
- OAuth2 / OIDC server. (pk-auth is a passkey + recovery layer, not an IdP.)
- SAML.
- TOTP authenticator apps (Google Authenticator etc.) — only SMS OTP is in scope, and only for phone verification.
- Push notifications.
- Admin console UI.
- Account recovery via support workflow (KYC, identity proofing).
- Federation / SSO.
- Hardware-backed key attestation enforcement (MDS3 fetch). Hook is present; implementation deferred.
- Redis-backed challenge store. (Postgres and DynamoDB cover it; add only on real need.)

---

## 14. First Action

Read this entire document. Then post a short plan back as a comment in `docs/plan-phase-0.md` listing the exact tasks for phase 0 and any clarifying questions before writing code. Wait for human approval, then execute phase 0.

---

*End of brief.*
