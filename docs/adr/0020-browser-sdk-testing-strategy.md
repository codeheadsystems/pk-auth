# 20. Browser SDK testing strategy

Date: 2026-06-18

## Status

Accepted.

## Context

The TypeScript browser SDK (`clients/passkeys-browser/`) exercises ceremony flows that span several
cooperating pieces: the WebAuthn browser API, the fetch layer, CBOR/base64url encoding, and the
pk-auth server's registration and authentication endpoints. There are three distinct ways to test
this code:

1. **Pure unit tests with mocks** — each component is tested in isolation; collaborators are
   replaced with mock objects that assert call sites.
2. **Simulated-environment unit tests** — a lightweight in-memory HTTP server (no real Java process)
   handles `/auth/**` requests while a Node.js runtime stands in for the browser. Tests drive the
   full client stack against this fake server, with per-test control over server behavior.
3. **Integration / end-to-end tests** — the real Java server runs (via Docker or a local process)
   and a headless Chromium browser executes the WebAuthn flow over the network.

The developer-experience constraint that anchors the comparison is: **a developer must be able to
open an IDE and run unit tests without unreasonable setup**. "Reasonable" means `npm install`.
"Unreasonable" means Docker, a running JVM, or a Chrome binary — those are prerequisites for
integration work, not for exploring a specific client code path.

Pure mocks (option 1) let each component be exercised in total isolation and are excellent for
corner cases that are hard to trigger otherwise, but they bind tests to implementation details
(which function was called, in what order) and leave the seams between components untested.

A simulated environment (option 2) replaces only the I/O boundary — the HTTP server and the
browser WebAuthn API — while running the full SDK stack in Node.js. It tests the integration
points between components without Docker or a real browser. It is easy to step-through-debug in
an IDE and straightforward to trigger failure paths (server timeouts, unexpected status codes,
authenticator errors) that would be cumbersome to produce against a real server.

End-to-end tests (option 3) give the strongest production signal — real crypto, real browser
security boundaries, real server persistence — but are the most expensive to set up, the slowest
to run, and the hardest to steer toward a specific code path or failure mode. Debugging requires
coordinating client and server concurrently.

The project already runs Playwright end-to-end suites under `examples/` (opt-in via
`PK_RUN_E2E=1`). The question this ADR resolves is what the *primary* unit testing strategy for
the SDK itself should be and how the three approaches relate to one another.

## Decision

**Prefer the simulated-environment approach (option 2) as the primary unit-testing strategy for
the browser SDK.** Option 1 (mock-based) is a valid complement for edge cases. Option 3
(end-to-end) is the existing Playwright suite under `examples/`.

Concretely:

- **Simulated environment** — a lightweight Node.js HTTP server stubs the pk-auth `/auth/**`
  endpoints in memory. Per-test fixtures can replace any server response (status code, body,
  timing) to exercise specific client behavior without a running JVM. The WebAuthn browser API
  (`navigator.credentials.create` / `.get`) is replaced with a fake authenticator that produces
  structurally valid CBOR/COSE artifacts. No Docker. No Chrome. Tests run with `npm test` from
  any IDE that can drive `vitest`.
- **Mock-based unit tests** remain appropriate when a failure mode is difficult to reproduce in
  the simulated environment (e.g. a network socket close mid-response, a CBOR encoding edge case)
  or when a very specific internal behavior needs pinning. They are not the default.
- **End-to-end tests** (`PK_RUN_E2E=1`) provide the integration gate against the real Java server
  and a real browser. They gate CI but are not expected to cover the full error-path matrix — that
  is the simulated environment's job.

The simulated environment should remain flexible (tests can inject arbitrary server responses) but
is intentionally *not* production-hardened (no persistence, no rate limiting, no challenge
store). Its only contract is behavioral fidelity to the real server's happy path and
well-defined error responses.

## Consequences

- **Positive — seam coverage without infra cost.** The integration points between the fetch layer,
  encoding, and ceremony orchestration are exercised in every unit test run; regressions at those
  seams surface immediately without Docker or a browser.
- **Positive — controllable failure paths.** Server timeouts, 4xx/5xx responses, and
  authenticator failures can be injected deterministically, producing test coverage that is
  impractical to achieve against a real server.
- **Positive — IDE-friendly.** `npm install` is the only prerequisite; tests run and debug in
  any IDE with a Node.js adapter.
- **Positive — loose coupling.** Tests assert observable outcomes (resolved/rejected promises,
  returned credential objects) rather than internal call sequences, so internal refactors do not
  require test rewrites.
- **Negative — the fake server and fake authenticator must stay in sync with the real
  implementations.** If the Java server changes a response shape, the simulated server must be
  updated or tests will silently diverge from production. The end-to-end suite is the backstop.
- **Negative — the Node.js runtime is not a browser.** Subtle browser-specific behaviors (CSP,
  secure-context enforcement, platform authenticator UX) are not exercised by the simulated
  environment; only the end-to-end suite can catch those.
- **Constraint — end-to-end tests remain opt-in** (`PK_RUN_E2E=1`) and are not expected to cover
  the full failure matrix. They validate the happy path and critical flows against real infra;
  the unit suite owns error-path breadth.
