# pk-auth Micronaut demo

A runnable Micronaut application exercising every pk-auth flow against the testkit's in-memory SPIs.

## Running

```sh
./gradlew :examples:micronaut-demo:run
```

The application boots on `http://localhost:8080`. Endpoints:

- `POST /auth/passkeys/registration/start`
- `POST /auth/passkeys/registration/finish`
- `POST /auth/passkeys/authentication/start`
- `POST /auth/passkeys/authentication/finish` (returns a JWT in both the body and the
  `Authorization` header on success)
- `GET /auth/admin/account` (requires `Authorization: Bearer <jwt>`)
- `GET /auth/admin/credentials`
- `PATCH /auth/admin/credentials/{credentialIdB64}` (body: `{"label":"..."}`)
- `DELETE /auth/admin/credentials/{credentialIdB64}`
- `POST /auth/admin/backup-codes/regenerate`
- `GET /auth/admin/backup-codes/count`
- `POST /auth/admin/email/start-verification` (body: `{"email":"..."}`)
- `POST /auth/admin/email/complete-verification` (body: `{"token":"..."}`; unauthenticated)
- `POST /auth/admin/phone/start-verification` (body: `{"phone":"+15551234567"}`)
- `POST /auth/admin/phone/complete-verification` (body: `{"phone":"...","code":"123456"}`)

## Persistence flavours

The demo defaults to the testkit's in-memory SPIs, so it runs without external infrastructure. Real
persistence is wired in as follows:

- JDBI and Postgres: add `pk-auth-persistence-jdbi` and provide a `Jdbi` bean.
- DynamoDB: add `pk-auth-persistence-dynamodb` and provide `DynamoDbClient` and
  `DynamoDbEnhancedClient` beans plus a `PkAuthDynamoTables`.

A factory that surfaces those repositories replaces `InMemoryPersistenceFactory`.

The [`docker-compose.yml`](./docker-compose.yml) ships a Postgres 16 and DynamoDB Local stack for
exercising those backends. The default in-memory profile needs none of it:

```bash
docker compose up -d
```

## Frontend

The demo's SPA lives in `src/main/resources/public/index.html` and `demo.js`, both of which consume
the shared `@pk-auth/passkeys-browser` SDK. The `processResources` Copy task bundles the SDK into
the demo's classpath at build time, and `StaticAssetsController` serves it at
`/passkeys-browser/index.js`.

The idiomatic Micronaut binding is `micronaut.router.static-resources` in `application.yml`. That
binding does not resolve the classpath path in this demo's runtime, so the controller serves the
three files explicitly. A new project can use the idiomatic binding.

The `run` task sets `pkauth.relying-party.id=localhost` (and the related keys) as JVM system
properties. Micronaut's nested `@ConfigurationProperties` binding does not reliably propagate the
YAML keys through `PkAuthConfiguration.RelyingParty`.

## End-to-end tests

Playwright drives the full registration, login, passkey management, backup codes, magic link, and
OTP flow against Chrome's CDP virtual WebAuthn authenticator:

```sh
(cd examples/micronaut-demo/e2e && npm install)
(cd examples/micronaut-demo/e2e && npx playwright test)
```

The Playwright config's `webServer` block starts the demo on demand via
`./gradlew :examples:micronaut-demo:run`. With `PK_DEMO_EXTERNAL=1`, the suite runs against a
pre-started demo.
