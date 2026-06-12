# Getting Started with pk-auth

A guide for developers who are about to drop pk-auth into a JVM project for
the first time. Start at the top, jump to whatever section answers your
current question.

## 1. The five-year-old version

Your app needs to know **who is logging in**. The old way was to store a
password — the user types it, you hash it, you compare it. That has problems:
users reuse passwords, phishing sites steal them, your database gets dumped
and now every password is on the internet.

The new way is a **passkey**. The user's device (phone, laptop, hardware key)
holds a tiny secret that *never leaves the device*. When the user logs in,
the device proves it owns that secret without revealing it. There is nothing
for an attacker to steal from your server, and nothing for the user to type
into a fake site.

pk-auth is **the part of your app that does the passkey dance**. It speaks
the WebAuthn protocol with the user's browser, remembers which passkey
belongs to which user, and gives you back a short-lived **JWT token** at the
end that you can use to identify the user on later requests.

What pk-auth is **not**:

- It's **not your user database.** It doesn't store names, emails, or
  permissions. You bring your existing `users` table; pk-auth just stores
  the passkeys (public keys + counters) that point at user IDs you give it.
- It's **not a SaaS.** It's a library — code you compile into your own
  application. Nothing leaves your servers.
- It's **not Spring-only.** It works with Spring Boot 4, Dropwizard 5, or
  Micronaut 4. Same wire contract on all three, same admin endpoints, same
  TypeScript SDK for the browser.

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

pk-auth sits *between* the browser and your app. It handles the cryptographic
parts. You handle "who is this user, and what are they allowed to do?"

### The simplest possible adoption

If your app is Spring Boot 4 today, adoption is roughly:

1. Add `pk-auth-spring-boot-starter` to your build.
2. Implement **one** Spring bean — `UserLookup` — that knows how to find a
   user in *your* user table by username, by email, or by an opaque byte ID
   that pk-auth gives you.
3. Set three required config values: `pkauth.relying-party.id` (your
   domain), `pkauth.relying-party.origins` (your HTTPS URLs), and
   `pkauth.jwt.secret` (a 32+ byte secret for signing JWTs).
4. Start your app. The endpoints under `/auth/passkeys/**` and `/auth/admin/**`
   now exist. Wire the browser SDK (`@pk-auth/passkeys-browser`) into your
   UI, and login is done.

You'll be using in-memory storage for the passkeys themselves until you
plug in a real persistence module — totally fine for the first run.

## 2. What's in the box

The project ships as a set of related JARs. You pick the ones you need:

### Always required

| Module | What it does | When you need it |
|---|---|---|
| `pk-auth-core` | The framework-neutral ceremony engine. Has the WebAuthn logic, the JWT contract, all the SPI interfaces you might implement, and the result types you'll pattern-match. | Always — every other module depends on this. |
| `pk-auth-jwt` | Issues and validates HS256 JWTs. Houses the `TokenTtlPolicy` SPI (per-audience access-token TTLs) and the `AccessTokenStore` SPI (stateful, server-revocable access tokens — paved road for "logout everywhere"); the lighter-weight `RevocationCheck` SPI is also still here. | Always — pk-auth's authentication output is a JWT. |

### Pick one adapter (this is your framework binding)

| Module | What it does | When you need it |
|---|---|---|
| `pk-auth-spring-boot-starter` | Auto-configures controllers, the JWT filter, and bean defaults for Spring Boot 4 / Spring Security 7. | If your app is Spring Boot. |
| `pk-auth-dropwizard` | Ships a `ConfiguredBundle` you register with your Dropwizard `Application`. Uses Dagger 2 for DI (see [ADR 0004](./docs/adr/0004-dagger-for-dropwizard.md)). | If your app is Dropwizard 5. |
| `pk-auth-micronaut` | Provides `@Factory` beans + controllers + a plain `@Filter` JWT validator (deliberately not Micronaut Security; see [DESIGN.md §7](./DESIGN.md#micronaut-4)). | If your app is Micronaut 4. |

### Pick a persistence backend (or run on the testkit)

| Module | What it does | When you need it |
|---|---|---|
| `pk-auth-testkit` | In-memory implementations of every SPI plus a `FakeAuthenticator` you can drive WebAuthn ceremonies with from a unit test. | Always on the test classpath. Also fine for a five-minute demo on the main classpath. |
| `pk-auth-persistence-jdbi` | SPI implementations on JDBI 3 + Postgres + Flyway. Schema migrations run automatically. | When you want real storage and you already have Postgres. |
| `pk-auth-persistence-dynamodb` | SPI implementations on AWS SDK v2 DynamoDB Enhanced. One physical table, schema per item type (see [ADR 0008](./docs/adr/0008-dynamodb-single-table-design.md)). | When you want real storage on AWS. |

### Optional "alt-flow" modules

You only need these if you want pk-auth to handle the corresponding feature.
Skip them and the feature isn't exposed.

| Module | What it does | Why you'd add it |
|---|---|---|
| `pk-auth-backup-codes` | View-once Argon2id-hashed backup codes for account recovery. | Users will lose their phones; backup codes are the documented recovery path before "talk to support." |
| `pk-auth-magic-link` | Single-use email magic-link tokens. JWTs on the wire; consumed-JTI tracking via a swappable SPI. | Email verification, or a passwordless login alternative for users without a passkey-capable device. |
| `pk-auth-otp` | 6-digit SMS OTPs with attempt caps; codes are hashed with HMAC-SHA256 using a server-side pepper. | Phone verification. |
| `pk-auth-refresh-tokens` | Rotating refresh tokens with family-based replay defense. Adds `POST /auth/refresh`; on success returns a new refresh token + a fresh access JWT, on replay scorches the entire token family. Requires a `RefreshTokenRepository` SPI (JDBI / DynamoDB impls ship). See [ADR 0013](./docs/adr/0013-refresh-tokens-family-rotation.md). | When you need sessions longer than the access-token TTL without re-running a WebAuthn ceremony. |
| `pk-auth-admin-api` | Adds the `/auth/admin/**` endpoints (rename / delete passkeys, regenerate backup codes, account summary, email & phone verification). | Almost always — without it the UI can't manage credentials. |

### The browser SDK

| Module | What it does | When you need it |
|---|---|---|
| `clients/passkeys-browser` (`@pk-auth/passkeys-browser`) | Zero-dependency TypeScript SDK. `PkAuthCeremonyClient` wraps `navigator.credentials.{create,get}` and handles all the base64url ↔ ArrayBuffer conversions. `PkAuthAdminClient` calls the admin endpoints with a bearer token. ESM + CJS bundles. | If your frontend talks to pk-auth from a browser. Skip if you're calling the JSON endpoints from a non-browser client (mobile, server-to-server). |

The SDK is on npm — its version tracks the pk-auth release it speaks to:

```sh
npm install @pk-auth/passkeys-browser
```

## 3. What you have to do (the SPI surface)

pk-auth's design assumes **your app already has a user table**. It doesn't
want to own user data. The price you pay for that is implementing a small
SPI surface — the interfaces below — so pk-auth can reach into your world.

| SPI | Required? | What it does |
|---|---|---|
| `UserLookup` | **Yes** | Maps `(username, email) ↔ UserHandle`. `UserHandle` is an opaque byte ID pk-auth uses internally. Your implementation typically stores it as a `BYTEA` column on your existing `users` table. |
| `CredentialRepository` | **Yes** | Stores passkeys (the public key + counter + label per credential). |
| `ChallengeStore` | **Yes** | Issues short-lived ceremony challenges and atomically consumes them. |
| `BackupCodeRepository` | If you use backup codes | Stores hashed backup codes; supports atomic single-use claim. |
| `OtpRepository` | If you use OTP | Same shape as backup codes for SMS codes. |
| `EmailSender` | If you use magic links | `send(to, subject, body)` — wire your SMTP / SendGrid / Mailgun here. |
| `SmsSender` | If you use OTP | `send(phoneE164, body)` — wire Twilio / SNS / etc. here. |
| `AttestationTrustPolicy` | Optional | Default is "accept any attestation." Override only if you need FIDO MDS3 verification. |
| `OriginValidator` | Optional | Default reads from config (`pkauth.relying-party.origins`). Override for multi-tenant origin rules. |
| `ClockProvider` | Optional | Default is `Clock.systemUTC()`. Override in tests. |
| `ConsumedJtiStore` | Optional (multi-replica only) | In-memory Caffeine cache by default. Replace with a shared store (Redis, DynamoDB) once you run more than one replica with magic-link enabled. |
| `CeremonyRateLimiter` | Optional (multi-replica only) | In-memory per-IP / per-username throttle by default. Same multi-replica caveat as above. |
| `AccessTokenStore` | Optional (1.1.0) | Stateful access tokens. When wired, every issued JWT's JTI is persisted; the validator looks it up on every request, so deleting the row immediately invalidates the bearer. The shipped JDBI / DynamoDB implementations are the paved road; `AccessTokenStore.noop()` is the legacy default. |
| `RevocationCheck` | Optional | In-process deny-list for hosts that want to invalidate a small subset of tokens without persisting every issue. Orthogonal to `AccessTokenStore`. |
| `TokenTtlPolicy` | Optional (1.1.0) | Per-audience access-token TTL. Default is `TokenTtlPolicy.single(ttl)` — one TTL for every audience. Implement when web / cli / mobile clients need different token lifetimes from a single issuer. |
| `RefreshTokenRepository` | If `pk-auth-refresh-tokens` is enabled (1.1.0) | Storage for the rotating refresh-token primitive. The load-bearing `rotateAtomically` method must mark-used + insert-successor atomically; JDBI / DynamoDB / in-memory impls ship. |
| `UserDeletionListener` | Optional (1.1.0) | Hook for the `UserDeletionService` fan-out. Listeners for credentials, backup codes, OTPs, access tokens, and refresh tokens are auto-registered; add your own to clean up host-owned tables when a user is deleted. |

**Good news**: every required SPI has a working `InMemoryX` implementation in
`pk-auth-testkit`, so you can boot the whole stack with zero database work
to start. Swap in real implementations one at a time as you go.

## 4. What a real wire-up looks like (Spring example)

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

That's the minimum. Start the app, hit `/auth/passkeys/registration/start`
from the browser SDK, and you have passkey login.

## 5. What you get on the wire

Every adapter exposes the same JSON contract. The full table is in
[DESIGN.md §4](./DESIGN.md#4-the-wire-contract); the short version:

- **Ceremony endpoints** (unauthenticated):
  - `POST /auth/passkeys/registration/start` → returns WebAuthn `create()` options
  - `POST /auth/passkeys/registration/finish` → persists the new credential
  - `POST /auth/passkeys/authentication/start` → returns WebAuthn `get()` options
  - `POST /auth/passkeys/authentication/finish` → returns `{token: "<JWT>"}`
  - `POST /auth/refresh` → rotates a refresh token; returns `{refresh, access}` on success, `401 {detail}` on any failure. Only mounted when `pk-auth-refresh-tokens` is wired.

- **Admin endpoints** (require `Authorization: Bearer <jwt>`):
  - `GET    /auth/admin/account`
  - `GET    /auth/admin/credentials`
  - `PATCH  /auth/admin/credentials/{id}`
  - `DELETE /auth/admin/credentials/{id}`   (returns 409 if it would leave the user with zero passkeys)
  - `POST   /auth/admin/backup-codes/regenerate`
  - `GET    /auth/admin/backup-codes/count`
  - `POST   /auth/admin/email/{start,complete}-verification`
  - `POST   /auth/admin/phone/{start,complete}-verification`

Bytes on the wire are base64url with no padding. Errors are JSON
`{outcome, error, detail}` with a `Retry-After` header on `rate_limited`.

## 6. Look at the example apps

The fastest way to understand any of this is to run a demo. Each example
exercises every flow — registration (single + multiple passkeys), login,
list/rename/delete, backup-code regeneration, email magic links, SMS OTP —
on a single static-HTML page.

| Demo | Run command | Source |
|---|---|---|
| Spring Boot 4 | `./gradlew :examples:spring-boot-demo:run` | [`examples/spring-boot-demo/`](./examples/spring-boot-demo/) |
| Dropwizard 5 | `./gradlew :examples:dropwizard-demo:run` | [`examples/dropwizard-demo/`](./examples/dropwizard-demo/) |
| Micronaut 4 | `./gradlew :examples:micronaut-demo:run` | [`examples/micronaut-demo/`](./examples/micronaut-demo/) |

Open <http://localhost:8080> in any passkey-capable browser. The demos
default to the **testkit's in-memory adapters** so they need no Postgres,
no DynamoDB, no Twilio, no SMTP — magic-link tokens and SMS OTPs are
printed to the server console (`LoggingEmailSender` / `LoggingSmsSender`),
and you copy them back into the UI to complete the verification flows.

Each demo's `README.md` documents flags for switching to a real persistence
backend (`docker compose up -d` for Postgres or DynamoDB Local, then
`--demo.persistence=jdbi` or `--demo.persistence=dynamodb`).

For a contrast, **read all three demos' wiring code**. The framework
plumbing differs — Spring `@Configuration` beans vs. Dropwizard's Dagger
module vs. Micronaut's `@Factory` — but the **same SPIs get wired into
the same core** in every case. That's the load-bearing claim of this
project, and the three demos are the proof.

## 7. Where to go next

- **The wire and class details** — [`DESIGN.md`](./DESIGN.md).
- **Running it in production** — [`docs/operator-guide.md`](./docs/operator-guide.md).
- **Security stance** — [`docs/threat-model.md`](./docs/threat-model.md).
- **Why a thing is the way it is** — [`docs/adr/`](./docs/adr/).
- **SPI stability + versioning** — [`docs/stability.md`](./docs/stability.md).
- **Transactional behavior across SPIs** — [`docs/transactional-semantics.md`](./docs/transactional-semantics.md).
