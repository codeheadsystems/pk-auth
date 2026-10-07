# `@pk-auth/passkeys-browser`

Zero-dependency TypeScript SDK for the pk-auth wire contract. It is published to npm as
[`@pk-auth/passkeys-browser`](https://www.npmjs.com/package/@pk-auth/passkeys-browser), and its
version tracks the pk-auth server release it speaks to. The example apps in this repository consume
it through a relative `dist/` import (built by Gradle) instead of the published package. The
publish steps are in [`RELEASE.md`](../../RELEASE.md).

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

// Admin (requires a token)
await pk.admin.listCredentials();
await pk.admin.regenerateBackupCodes();
```

The clients are also exported individually, for hosts that need only part of the surface:

- `PkAuthCeremonyClient`: `startRegistration`, `register`, `startAuthentication`, `authenticate`.
- `PkAuthAdminClient`: `listCredentials`, `renameCredential`, `removeCredential`,
  `regenerateBackupCodes`, `remainingBackupCodes`, `startEmailVerification`,
  `completeEmailVerification`, `startPhoneVerification`, `completePhoneVerification`,
  `getAccount`.
- `PkAuthRefreshClient`: `refresh`.

### Conditional UI

```ts
await pk.ceremonies.authenticate({ conditional: true });
```

This passes `mediation: "conditional"` to the underlying `navigator.credentials.get` call, so the
browser can offer passkeys through the autofill UI before the user selects "Sign in".

### Ceremony path overrides

All three adapters (Spring Boot, Dropwizard, Micronaut) mount the ceremony endpoints at the
same `/auth/passkeys/...` paths, which are the SDK defaults, so no per-adapter override is
needed. The `paths` option is an escape hatch for hosts that remount the endpoints under a custom
prefix:

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

## Build and test

```sh
npm install
npm test         # vitest, jsdom env
npm run build    # tsup → dist/index.{js,cjs,d.ts}
```

`dist/` is gitignored. Gradle's `:buildPasskeysBrowserSdk` task (defined in the root
`build.gradle.kts`) runs `npm ci && npm run build` before each demo's `processResources`, so the
bundle is regenerated from source on every fresh clone. Iterating on the SDK in isolation uses the
npm commands above directly.
