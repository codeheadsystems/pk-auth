# pk-auth Dropwizard demo

A single-page demo of the [pk-auth Dropwizard adapter](../../pk-auth-dropwizard). It boots a
Dropwizard 5 application with the in-memory testkit SPIs, mounts the four passkey ceremony endpoints
under `/auth/passkeys/**` and the admin endpoints under `/auth/admin/**`, and serves an HTML and
vanilla-JS page that drives the full flow with `navigator.credentials.{create,get}`.

## Running

```bash
./gradlew :examples:dropwizard-demo:run
```

The application listens on `http://localhost:8080`. A passkey-capable browser (Chrome, Edge, Safari,
or Firefox 130+) opens the page. The platform authenticator handles the WebAuthn ceremony, the
server stores the credential in memory, and the post-login page renders the decoded JWT and the
admin controls.

`Ctrl-C` stops the application.

## Demo contents

| Section | Endpoint | Notes |
|---|---|---|
| Register passkey | `POST /auth/passkeys/registration/start`, `POST /auth/passkeys/registration/finish` | The first credential creates the user account; later calls add further passkeys (multi-passkey). |
| Sign in | `POST /auth/passkeys/authentication/start`, `POST /auth/passkeys/authentication/finish` | On success returns a pk-auth JWT (HS256). |
| Account summary | `GET /auth/admin/account` | Credential count, remaining backup codes, verification flags. |
| List, rename, delete passkeys | `GET/PATCH/DELETE /auth/admin/credentials*` | The last-credential guard rejects deletions that would lock the user out. |
| Backup codes | `POST /auth/admin/backup-codes/regenerate`, `GET /auth/admin/backup-codes/count` | Plaintext is shown exactly once. |
| Magic link | `POST /auth/admin/email/start-verification` | `LoggingEmailSender` writes the URL to the server log. The token is pasted back into the page, or `complete-verification` is called directly. |
| Phone OTP | `POST /auth/admin/phone/start-verification`, `POST /auth/admin/phone/complete-verification` | `LoggingSmsSender` writes the code to the server log. |
| JWT contents | Rendered client-side | After login the page shows the decoded JWT payload. |

## Persistence variants

`DemoApplication` selects the backing store from the `PKAUTH_PERSISTENCE` environment variable, or
from the `pkauth.persistence` system property when the variable is unset. The values are `memory`
(the default), `jdbi`, and `dynamodb`:

```bash
PKAUTH_PERSISTENCE=dynamodb ./gradlew :examples:dropwizard-demo:run
```

All three values currently use the in-memory SPIs, so the demo runs without external services. The
[`docker-compose.yml`](./docker-compose.yml) ships a Postgres 16 and DynamoDB Local stack for use
once the JDBI and DynamoDB modules provide "all-in-one" factories:

```bash
docker compose up -d
```

## End-to-end tests

Playwright drives the full registration, login, passkey management, backup codes, magic link, and
OTP flow against Chrome's CDP virtual WebAuthn authenticator:

```sh
(cd examples/dropwizard-demo/e2e && npm install)
(cd examples/dropwizard-demo/e2e && npx playwright test)
```

The Playwright config's `webServer` block starts the demo on demand via
`./gradlew :examples:dropwizard-demo:run`. With `PK_DEMO_EXTERNAL=1`, the suite runs against a
pre-started demo.

## Production caveats

The demo is not a production deployment recipe. It differs from a production deployment in three
ways:

- The JWT signing secret is hard-coded.
- All persistence is process-local and erased on restart.
- `LoggingEmailSender` and `LoggingSmsSender` print verification tokens to the application log,
  which is a security hole in production.

Production wiring is described in [`docs/operator-guide.md`](../../docs/operator-guide.md).
