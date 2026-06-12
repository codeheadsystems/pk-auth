# pk-auth Micronaut demo

A runnable Micronaut application exercising every pk-auth flow against the testkit's in-memory SPIs.

## Run

```sh
./gradlew :examples:micronaut-demo:run
```

The app boots on `http://localhost:8080`. Endpoints:

- `POST /auth/passkeys/registration/start`
- `POST /auth/passkeys/registration/finish`
- `POST /auth/passkeys/authentication/start`
- `POST /auth/passkeys/authentication/finish` — returns a JWT in both the body and the `Authorization` header on success.
- `GET /auth/admin/account` (requires `Authorization: Bearer <jwt>`)
- `GET /auth/admin/credentials`
- `PATCH /auth/admin/credentials/{credentialIdB64}` (body: `{"label":"..."}`)
- `DELETE /auth/admin/credentials/{credentialIdB64}`
- `POST /auth/admin/backup-codes/regenerate`
- `GET /auth/admin/backup-codes/count`
- `POST /auth/admin/email/start-verification` (body: `{"email":"..."}`)
- `POST /auth/admin/email/complete-verification` (body: `{"token":"..."}`) — unauthenticated.
- `POST /auth/admin/phone/start-verification` (body: `{"phone":"+15551234567"}`)
- `POST /auth/admin/phone/complete-verification` (body: `{"phone":"...","code":"123456"}`)

## Persistence flavors

The demo defaults to the testkit's in-memory SPIs so it runs without external infra. To wire real
persistence:

- **JDBI / Postgres** — add `pk-auth-persistence-jdbi` and provide a `Jdbi` bean.
- **DynamoDB** — add `pk-auth-persistence-dynamodb` and provide `DynamoDbClient` / `DynamoDbEnhancedClient` beans plus a `PkAuthDynamoTables`.

Replace the `InMemoryPersistenceFactory` with a factory that surfaces those repos.

For hands-on poking at those backends, [`docker-compose.yml`](./docker-compose.yml) ships a
Postgres 16 + DynamoDB Local stack (none of which the default in-memory profile needs):

```bash
docker compose up -d
```

## Frontend

The demo's SPA lives in `src/main/resources/public/index.html` and `demo.js`, both of
which consume the shared `@pk-auth/passkeys-browser` SDK (bundled into the demo's
classpath at build time by the `processResources` Copy task). The SDK is served at
`/passkeys-browser/index.js` via the `StaticAssetsController`.

> The idiomatic Micronaut path here would be `micronaut.router.static-resources` in
> `application.yml`. That binding wasn't picking the classpath path up in this demo's
> runtime, so the controller serves the three files explicitly. A fresh project would
> not need the workaround.

The demo sets `pkauth.relying-party.id=localhost` (and friends) via JVM system
properties on the `run` task — Micronaut's nested `@ConfigurationProperties` binding
didn't propagate the YAML keys through `PkAuthConfiguration.RelyingParty` reliably.

## End-to-end tests

Playwright drives the full registration → login → manage passkeys → backup codes →
magic link → OTP flow against Chrome's CDP virtual WebAuthn authenticator:

```sh
(cd examples/micronaut-demo/e2e && npm install)
(cd examples/micronaut-demo/e2e && npx playwright test)
```

The Playwright config's `webServer` block starts the demo on demand via
`./gradlew :examples:micronaut-demo:run`. Set `PK_DEMO_EXTERNAL=1` to run against a
pre-started demo.
