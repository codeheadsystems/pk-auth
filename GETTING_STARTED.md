# Getting Started with pk-auth

pk-auth adds passkey authentication to a Spring Boot, Dropwizard, or Micronaut application, and the
host's own user table stays in place.

## 1. Concepts

An application needs to know who is logging in. The old way was to store a password: the user types
it, the application hashes it and compares. That has problems. Users reuse passwords, phishing
sites steal them, and a dumped database puts every password on the internet.

The new way is a **passkey**. The user's device (phone, laptop, hardware key) holds a tiny secret
that never leaves the device. At login, the device proves it owns that secret without revealing it.
Nothing is left for an attacker to steal from the server, and nothing is left for the user to type
into a fake site.

pk-auth is the part of the application that performs the passkey exchange. It speaks the WebAuthn
protocol with the user's browser, records which passkey belongs to which user, and returns a
short-lived **JWT** at the end, which identifies the user on later requests.

The scope of pk-auth has three limits:

- pk-auth is not the user database. It does not store names, emails, or permissions. The host keeps
  its existing `users` table, and pk-auth stores only the passkeys (public keys + counters) that
  point at user IDs the host supplies.
- pk-auth is not a SaaS. It is a library, code compiled into the host application. Nothing leaves
  the host's servers.
- pk-auth is not Spring-only. It works with Spring Boot 4, Dropwizard 5, or Micronaut 4, with the
  same wire contract on all three, the same admin endpoints, and the same TypeScript SDK for the
  browser.

### The mental model

```
┌─────────────────┐    pk-auth does this    ┌─────────────────────┐
│  Your user's    │    ◄────────────────►   │  Your application   │
│  browser + a    │   WebAuthn ceremony     │  (with pk-auth      │
│  passkey device │                         │   wired in)         │
└─────────────────┘                         └─────────┬───────────┘
                                                      │
                                                      │ You still own:
                                                      │  - the users table
                                                      ▼  - your business logic
                                                ┌────────────┐
                                                │  Your DB   │
                                                └────────────┘
```

pk-auth sits between the browser and the application. It handles the cryptographic parts. The host
handles who a user is and what the user is allowed to do.

### Minimal Spring Boot adoption

For a Spring Boot 4 application, adoption is roughly:

1. Add `pk-auth-spring-boot-starter` to the build.
2. Implement one Spring bean, `UserLookup`, that finds a user in the application's user table by
   username, by email, or by an opaque byte ID that pk-auth supplies.
3. Set three required config values: `pkauth.relying-party.id` (the domain),
   `pkauth.relying-party.origins` (the HTTPS URLs), and `pkauth.jwt.secret` (a 32+ byte secret for
   signing JWTs).
4. Start the application. The endpoints under `/auth/passkeys/**` and `/auth/admin/**` now exist.
   Wire the browser SDK (`@pk-auth/passkeys-browser`) into the UI, and login is done.

Passkeys are held in in-memory storage until a real persistence module is plugged in, which is
sufficient for a first run.

## 2. Modules

The project ships as a set of related JARs, and the host picks the ones it needs.

### Required modules

| Module | What it does | When it is needed |
|---|---|---|
| `pk-auth-core` | The framework-neutral ceremony engine. Has the WebAuthn logic, the JWT contract, all the SPI interfaces the host might implement, and the result types the host pattern-matches. | Always; every other module depends on it. |
| `pk-auth-jwt` | Issues and validates HS256 JWTs. Houses the `TokenTtlPolicy` SPI (per-audience access-token TTLs) and the `AccessTokenStore` SPI (stateful, server-revocable access tokens, the paved road for "logout everywhere"); the lighter-weight `RevocationCheck` SPI also lives here. | Always; pk-auth's authentication output is a JWT. |

### Adapter modules

One adapter is chosen as the framework binding.

| Module | What it does | When it is needed |
|---|---|---|
| `pk-auth-spring-boot-starter` | Auto-configures controllers, the JWT filter, and bean defaults for Spring Boot 4 / Spring Security 7. | When the application is Spring Boot. |
| `pk-auth-dropwizard` | Ships a `ConfiguredBundle` that the host registers with its Dropwizard `Application`. Uses Dagger 2 for DI (see [ADR 0004](./docs/adr/0004-dagger-for-dropwizard.md)). | When the application is Dropwizard 5. |
| `pk-auth-micronaut` | Provides `@Factory` beans + controllers + a plain `@Filter` JWT validator (no Micronaut Security; see [DESIGN.md §7](./DESIGN.md#micronaut-4)). | When the application is Micronaut 4. |

### Persistence modules

A persistence backend is chosen, or the host runs on the testkit.

| Module | What it does | When it is needed |
|---|---|---|
| `pk-auth-testkit` | In-memory implementations of every SPI plus a `FakeAuthenticator` that drives WebAuthn ceremonies from a unit test. | Always on the test classpath. Also suitable for a five-minute demo on the main classpath. |
| `pk-auth-persistence-jdbi` | SPI implementations on JDBI 3 + Postgres + Flyway. The host application runs the shipped migrations with its own Flyway setup (see `PkAuthJdbiSchema` and the [operator guide](./docs/operator-guide.md#3-persistence-migrations)); no adapter runs them. | When real storage is wanted and Postgres already exists. |
| `pk-auth-persistence-dynamodb` | SPI implementations on AWS SDK v2 DynamoDB Enhanced. One physical table, schema per item type (see [ADR 0008](./docs/adr/0008-dynamodb-single-table-design.md)). | When real storage on AWS is wanted. |

### Optional alt-flow modules

These modules are needed only when pk-auth handles the corresponding feature. Without a module, the
feature is not exposed.

| Module | What it does | Reason to add it |
|---|---|---|
| `pk-auth-backup-codes` | View-once Argon2id-hashed backup codes for account recovery. | Users lose their phones; backup codes are the documented recovery path before contacting support. |
| `pk-auth-magic-link` | Single-use email magic-link tokens. JWTs on the wire; consumed-JTI tracking via a swappable SPI. | Email verification, or a passwordless login alternative for users without a passkey-capable device. |
| `pk-auth-otp` | 6-digit SMS OTPs with attempt caps; codes are hashed with HMAC-SHA256 using a server-side pepper. | Phone verification. |
| `pk-auth-refresh-tokens` | Rotating refresh tokens with family-based replay defence. Adds `POST /auth/refresh`; on success returns a new refresh token + a fresh access JWT, on replay scorches the entire token family. Requires a `RefreshTokenRepository` SPI (JDBI / DynamoDB impls ship). See [ADR 0013](./docs/adr/0013-refresh-tokens-family-rotation.md). | Sessions that outlast the access-token TTL without re-running a WebAuthn ceremony. |
| `pk-auth-admin-api` | Adds the `/auth/admin/**` endpoints (rename / delete passkeys, regenerate backup codes, account summary, email & phone verification). | Almost always; without it the UI cannot manage credentials. |

### The browser SDK

| Module | What it does | When it is needed |
|---|---|---|
| `clients/passkeys-browser` (`@pk-auth/passkeys-browser`) | Zero-dependency TypeScript SDK. `PkAuthCeremonyClient` wraps `navigator.credentials.{create,get}` and handles all the base64url ↔ ArrayBuffer conversions. `PkAuthAdminClient` calls the admin endpoints with a bearer token. ESM + CJS bundles. | When the frontend talks to pk-auth from a browser. Not needed for non-browser clients (mobile, server-to-server) that call the JSON endpoints. |

The SDK is on npm, and its version tracks the pk-auth release it speaks to:

```sh
npm install @pk-auth/passkeys-browser
```

## 3. SPI surface

pk-auth assumes that the host application already has a user table, and it does not own user data.
The cost of that assumption is a small SPI surface, the interfaces below, through which pk-auth
reaches the host's data.

| SPI | Required? | What it does |
|---|---|---|
| `UserLookup` | Yes | Maps `(username, email) ↔ UserHandle`. `UserHandle` is an opaque byte ID pk-auth uses internally. An implementation typically stores it as a `BYTEA` column on the existing `users` table. |
| `CredentialRepository` | Yes | Stores passkeys (the public key + counter + label per credential). |
| `ChallengeStore` | Yes | Issues short-lived ceremony challenges and atomically consumes them. |
| `BackupCodeRepository` | When backup codes are used | Stores hashed backup codes; supports atomic single-use claim. |
| `OtpRepository` | When OTP is used | Same shape as backup codes for SMS codes. |
| `EmailSender` | When magic links are used | `send(to, subject, body)`; the host wires SMTP / SendGrid / Mailgun behind it. |
| `SmsSender` | When OTP is used | `send(phoneE164, body)`; the host wires Twilio / SNS / etc. behind it. |
| `AttestationTrustPolicy` | Optional | Default is "accept any attestation." Overridden only for FIDO MDS3 verification. |
| `OriginValidator` | Optional | Default reads from config (`pkauth.relying-party.origins`). Overridden for multi-tenant origin rules. |
| `ClockProvider` | Optional | Default is `Clock.systemUTC()`. Overridden in tests. |
| `ConsumedJtiStore` | Optional (multi-replica only) | In-memory Caffeine cache by default. Replaced with a shared store (Redis, DynamoDB) once more than one replica runs with magic-link enabled. |
| `CeremonyRateLimiter` | Optional (multi-replica only) | In-memory per-IP / per-username throttle by default. The multi-replica caveat of `ConsumedJtiStore` applies. |
| `AccessTokenStore` | Optional (1.1.0) | Stateful access tokens. When wired, every issued JWT's JTI is persisted; the validator looks it up on every request, so deleting the row immediately invalidates the bearer. The shipped JDBI / DynamoDB implementations are the paved road; `AccessTokenStore.noop()` is the legacy default. |
| `RevocationCheck` | Optional | In-process deny-list for hosts that want to invalidate a small subset of tokens without persisting every issue. Orthogonal to `AccessTokenStore`. |
| `TokenTtlPolicy` | Optional (1.1.0) | Per-audience access-token TTL. Default is `TokenTtlPolicy.single(ttl)`, one TTL for every audience. Implemented when web / cli / mobile clients need different token lifetimes from a single issuer. |
| `RefreshTokenRepository` | When `pk-auth-refresh-tokens` is enabled (1.1.0) | Storage for the rotating refresh-token primitive. The load-bearing `rotateAtomically` method must mark-used + insert-successor atomically; JDBI / DynamoDB / in-memory impls ship. |
| `UserDeletionListener` | Optional (1.1.0) | Hook for the `UserDeletionService` fan-out. Listeners for credentials, backup codes, OTPs, access tokens, and refresh tokens are auto-registered; hosts add their own to clean up host-owned tables when a user is deleted. |

Every required SPI has a working `InMemoryX` implementation in `pk-auth-testkit`, so the whole
stack boots with zero database work. Real implementations swap in one at a time.

## 4. Spring wiring example

```kotlin
// build.gradle.kts
dependencies {
  implementation("com.codeheadsystems:pk-auth-spring-boot-starter:<version>")
  implementation("com.codeheadsystems:pk-auth-admin-api:<version>")          // /auth/admin/**
  implementation("com.codeheadsystems:pk-auth-persistence-jdbi:<version>")   // real Postgres storage
  implementation("com.codeheadsystems:pk-auth-backup-codes:<version>")       // optional
  implementation("com.codeheadsystems:pk-auth-magic-link:<version>")         // optional
  implementation("com.codeheadsystems:pk-auth-otp:<version>")                // optional
}
```

```yaml
# application.yml
pkauth:
  relying-party:
    id: example.com                       # the eTLD+1 — not "auth.example.com"
    name: My App
    origins: ["https://example.com"]
  jwt:
    secret: ${PKAUTH_JWT_SECRET}          # >= 32 bytes; injected via env
    issuer: https://example.com
    audience: example.com
```

```java
// UserLookupBean.java — the only Spring-specific code you have to write.
@Component
class UserLookupBean implements UserLookup {
  private final UserService users;        // your existing service

  @Override public Optional<UserHandle> findHandleByUsername(String username) {
    return users.findByUsername(username).map(u -> UserHandle.of(u.getPkAuthHandle()));
  }
  @Override public Optional<UserView> findViewByHandle(UserHandle handle) {
    return users.findByPkAuthHandle(handle.bytes())
        .map(u -> new UserView(handle, u.getUsername(), u.getDisplayName()));
  }
  @Override public UserHandle getOrCreateHandle(String username) {
    return UserHandle.of(users.findOrCreateByUsername(username).getPkAuthHandle());
  }
}
```

This is the minimum wiring. With it and a started application, the browser SDK reaches
`/auth/passkeys/registration/start`, and passkey login works.

## 5. Wire contract summary

Every adapter exposes the same JSON contract. The full table is in
[DESIGN.md §4](./DESIGN.md#4-the-wire-contract); in short:

- Ceremony endpoints (unauthenticated):
  - `POST /auth/passkeys/registration/start` → returns WebAuthn `create()` options
  - `POST /auth/passkeys/registration/finish` → persists the new credential
  - `POST /auth/passkeys/authentication/start` → returns WebAuthn `get()` options
  - `POST /auth/passkeys/authentication/finish` → returns `{token: "<JWT>"}`
  - `POST /auth/refresh` → rotates a refresh token; returns `{refresh, access}` on success,
    `401 {detail}` on any failure. Only mounted when `pk-auth-refresh-tokens` is wired.

- Admin endpoints (require `Authorization: Bearer <jwt>`):
  - `GET    /auth/admin/account`
  - `GET    /auth/admin/credentials`
  - `PATCH  /auth/admin/credentials/{id}`
  - `DELETE /auth/admin/credentials/{id}`   (returns `409` if it would leave the user with zero
    passkeys)
  - `POST   /auth/admin/backup-codes/regenerate`
  - `GET    /auth/admin/backup-codes/count`
  - `POST   /auth/admin/email/{start,complete}-verification`
  - `POST   /auth/admin/phone/{start,complete}-verification`

Bytes on the wire are base64url with no padding. Errors are JSON `{outcome, error, detail}` with a
`Retry-After` header on `rate_limited`.

## 6. Example applications

Each demo exercises every flow (registration with single and multiple passkeys, login,
list/rename/delete, backup-code regeneration, email magic links, SMS OTP) on a single static-HTML
page, so running one is the fastest way to see the system work.

| Demo | Run command | Source |
|---|---|---|
| Spring Boot 4 | `./gradlew :examples:spring-boot-demo:run` | [`examples/spring-boot-demo/`](./examples/spring-boot-demo/) |
| Dropwizard 5 | `./gradlew :examples:dropwizard-demo:run` | [`examples/dropwizard-demo/`](./examples/dropwizard-demo/) |
| Micronaut 4 | `./gradlew :examples:micronaut-demo:run` | [`examples/micronaut-demo/`](./examples/micronaut-demo/) |

Each demo serves at <http://localhost:8080>, in any passkey-capable browser. The demos default to
the testkit's in-memory adapters, so they need no Postgres, no DynamoDB, no Twilio, and no SMTP.
Magic-link tokens and SMS OTPs are printed to the server console (`LoggingEmailSender` /
`LoggingSmsSender`), and they are copied back into the UI to complete the verification flows.

Each demo's `README.md` documents how to switch to a real persistence backend, and
`docker compose up -d` starts Postgres or DynamoDB Local. The selector differs per demo. The Spring
Boot demo takes `--demo.persistence=jdbi` or `--demo.persistence=dynamodb`, and the Dropwizard demo
reads the `PKAUTH_PERSISTENCE` environment variable. The Micronaut demo replaces
`InMemoryPersistenceFactory` with a factory that surfaces the real repositories.

The framework plumbing in the three demos differs: Spring `@Configuration` beans, Dropwizard's
Dagger module, and Micronaut's `@Factory`. In every case the same SPIs are wired into the same
core, and the three demos together show it.

## 7. Further reading

- Wire and class details: [`DESIGN.md`](./DESIGN.md).
- Running in production: [`docs/operator-guide.md`](./docs/operator-guide.md).
- Security stance: [`docs/threat-model.md`](./docs/threat-model.md).
- Decision rationale: [`docs/adr/`](./docs/adr/).
- SPI stability and versioning: [`docs/stability.md`](./docs/stability.md).
- Transactional behaviour across SPIs:
  [`docs/transactional-semantics.md`](./docs/transactional-semantics.md).
