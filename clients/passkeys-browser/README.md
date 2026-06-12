# `@pk-auth/passkeys-browser`

Zero-dependency TypeScript SDK for the pk-auth wire contract.
Published to npm as [`@pk-auth/passkeys-browser`](https://www.npmjs.com/package/@pk-auth/passkeys-browser);
its version tracks the pk-auth server release it speaks to. The example apps in
this repo consume it via a relative `dist/` import (built by Gradle) rather than
the published package. See [`RELEASE.md`](../../RELEASE.md) for the publish steps.

```sh
npm install @pk-auth/passkeys-browser
```

## API

```ts
import { PkAuthClient } from "@pk-auth/passkeys-browser";

const pk = new PkAuthClient({
  apiBase: "/",
  getToken: () => localStorage.getItem("pk-jwt"),
});

// Registration
await pk.ceremonies.register({ username: "alice", label: "MacBook" });

// Sign-in
const { token } = await pk.ceremonies.authenticate({ username: "alice" });
localStorage.setItem("pk-jwt", token);

// Admin (require a token)
await pk.admin.listCredentials();
await pk.admin.regenerateBackupCodes();
```

Two clients are exposed independently if a host only needs one half:

- `PkAuthCeremonyClient` — `startRegistration`, `register`, `startAuthentication`, `authenticate`.
- `PkAuthAdminClient` — `listCredentials`, `renameCredential`, `removeCredential`,
  `regenerateBackupCodes`, `remainingBackupCodes`, `startEmailVerification`,
  `completeEmailVerification`, `startPhoneVerification`, `completePhoneVerification`,
  `getAccount`.

### Conditional UI

```ts
await pk.ceremonies.authenticate({ conditional: true });
```

Wires `mediation: "conditional"` into the underlying `navigator.credentials.get` call,
so the browser can offer passkeys via autofill UI before the user clicks "Sign in."

### Overriding ceremony paths

All three adapters (Spring Boot, Dropwizard, Micronaut) mount the ceremony endpoints at the
same `/auth/passkeys/...` paths, which are the SDK defaults — no per-adapter override is
needed. The `paths` option remains an escape hatch for hosts that remount the endpoints under
a custom prefix:

```ts
new PkAuthCeremonyClient(options, {
  paths: {
    startReg: "/api/auth/passkeys/registration/start",
    finishReg: "/api/auth/passkeys/registration/finish",
    startAuth: "/api/auth/passkeys/authentication/start",
    finishAuth: "/api/auth/passkeys/authentication/finish",
  },
});
```

## Build / test

```sh
npm install
npm test         # vitest, jsdom env
npm run build    # tsup → dist/index.{js,cjs,d.ts}
```

`dist/` is gitignored — Gradle's `:buildPasskeysBrowserSdk` task (defined in the root
`build.gradle.kts`) runs `npm ci && npm run build` before each demo's `processResources`,
so the bundle is regenerated from source on every fresh clone. Run the npm commands above
directly when iterating on the SDK in isolation.
