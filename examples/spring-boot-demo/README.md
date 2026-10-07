# pk-auth Spring Boot demo

A single-page exercise of every flow in the pk-auth credential layer: passkey registration
(including multi-passkey), passkey login, list/rename/delete credentials, regenerate backup codes
(view-once), magic-link email verification, SMS OTP phone verification, and account summary. The
post-login UI also decodes the issued JWT and displays the claims.

## Running

The default profile boots with the testkit's in-memory adapters and needs no external services:

```sh
./gradlew :examples:spring-boot-demo:bootRun
# open http://localhost:8080
```

The `application` plugin's `run` task is interchangeable with `bootRun`:

```sh
./gradlew :examples:spring-boot-demo:run
```

### Switching persistence backends

Both JDBI and DynamoDB variants are selectable. `docker compose up -d` starts the external
services, and the `demo.persistence` property selects one or the other:

```sh
# Postgres-backed (Flyway migrations run at startup):
./gradlew :examples:spring-boot-demo:bootRun --args='--demo.persistence=jdbi'

# DynamoDB Local:
./gradlew :examples:spring-boot-demo:bootRun --args='--demo.persistence=dynamodb'
```

The wiring beans for `jdbi` and `dynamodb` are stubbed out in this demo. The runtime flag toggles
the property, and the host application supplies the actual `Jdbi` and `DynamoDbClient` beans. The
`memory` profile is the supported runnable path. The starter's tests validate the JDBI and DynamoDB
autoconfigs.

## Endpoint surface

The demo's HTML uses the standard pk-auth endpoints. The only demo-specific route is `GET /`, which
returns the SPA.

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/auth/passkeys/registration/start` | Begin registration |
| `POST` | `/auth/passkeys/registration/finish` | Finish registration |
| `POST` | `/auth/passkeys/authentication/start` | Begin assertion |
| `POST` | `/auth/passkeys/authentication/finish` | Finish assertion (mints JWT) |
| `GET` | `/auth/admin/account` | Current user summary |
| `GET` | `/auth/admin/credentials` | List passkeys |
| `PATCH` | `/auth/admin/credentials/{credentialId}` | Rename a passkey |
| `DELETE` | `/auth/admin/credentials/{credentialId}` | Delete a passkey |
| `POST` | `/auth/admin/backup-codes/regenerate` | View-once plaintext codes |
| `GET` | `/auth/admin/backup-codes/count` | Remaining count |
| `POST` | `/auth/admin/email/start-verification` | Send magic link |
| `POST` | `/auth/admin/email/complete-verification` | Consume token (unauthenticated) |
| `POST` | `/auth/admin/phone/start-verification` | Send OTP |
| `POST` | `/auth/admin/phone/complete-verification` | Verify OTP |

## End-to-end tests

Playwright drives the full registration, login, passkey management, backup codes, magic link, and
OTP flow against Chrome's CDP virtual WebAuthn authenticator:

```sh
(cd examples/spring-boot-demo/e2e && npm install)
(cd examples/spring-boot-demo/e2e && npx playwright test)
```

The Playwright config's `webServer` block starts the demo on demand via
`./gradlew :examples:spring-boot-demo:run`. With `PK_DEMO_EXTERNAL=1`, the suite runs against a
pre-started demo, for example in CI alongside Postgres and DynamoDB Local.

## Notes

- Magic-link tokens and SMS OTPs are logged to the server console by the demo's senders,
  `LoggingEmailSender` and `LoggingSmsSender`. The token or code is copied from the log and pasted
  into the form to complete the corresponding flow.
- The demo's SPA lives in `src/main/resources/static/index.html` and `demo.js`, both of which
  consume the `@pk-auth/passkeys-browser` SDK. The `processResources` Copy task bundles the SDK into
  the demo's static resources at build time.
- WebAuthn requires a secure origin. `http://localhost:8080` is secure-by-loopback in every major
  browser. Running the demo behind a remote host needs HTTPS.
- Virtual threads are enabled with `spring.threads.virtual.enabled=true`.
