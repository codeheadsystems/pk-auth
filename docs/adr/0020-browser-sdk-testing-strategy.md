# 20. Browser SDK testing strategy

Date: 2026-06-18

## Status

Accepted.

## Context

The TypeScript browser SDK (`clients/passkeys-browser/`) exercises ceremony flows that span several
cooperating pieces: the WebAuthn browser API, the fetch layer, CBOR/base64url encoding, and the
pk-auth server's registration and authentication endpoints. There are three distinct ways to test
this code:

1. Pure unit tests with mocks. Each component is tested in isolation, and collaborators are replaced
   with mock objects that assert call sites.
2. Simulated-environment unit tests. A lightweight in-memory HTTP server (no real Java process)
   handles `/auth/**` requests while a Node.js runtime stands in for the browser. Tests drive the
   full client stack against this fake server, with per-test control over server behaviour.
3. Integration and end-to-end tests. The real Java server runs (via Docker or a local process) and a
   headless Chromium browser executes the WebAuthn flow over the network.

The developer-experience constraint that anchors the comparison is that a developer must be able to
open an IDE and run unit tests without unreasonable setup. Reasonable setup means `npm install`.
Unreasonable setup means Docker, a running JVM, or a Chrome binary, which are prerequisites for
integration work and not for exploring a specific client code path.

Pure mocks (option 1) let each component be exercised in total isolation and suit corner cases that
are hard to trigger otherwise, but they bind tests to implementation details (which function was
called, in what order) and leave the seams between components untested.

A simulated environment (option 2) replaces only the I/O boundary (the HTTP server and the browser
WebAuthn API) while running the full SDK stack in Node.js. It tests the integration points between
components without Docker or a real browser. It is easy to step-through-debug in an IDE, and it
makes failure paths (server timeouts, unexpected status codes, authenticator errors) straightforward
to trigger where they would be cumbersome to produce against a real server.

End-to-end tests (option 3) give the strongest production signal (real crypto, real browser security
boundaries, real server persistence), but they are the most expensive to set up, the slowest to run,
and the hardest to steer toward a specific code path or failure mode. Debugging requires
coordinating client and server concurrently.

The project already runs Playwright end-to-end suites under `examples/` (opt-in via `PK_RUN_E2E=1`).
The open question is which approach is the primary unit testing strategy for the SDK itself and how
the three approaches relate to one another.

## Decision

The simulated-environment approach (option 2) is the primary unit-testing strategy for the browser
SDK. Option 1 (mock-based) is a valid complement for edge cases. Option 3 (end-to-end) is the
existing Playwright suite under `examples/`.

Concretely:

- Simulated environment: a lightweight Node.js HTTP server stubs the pk-auth `/auth/**` endpoints in
  memory. Per-test fixtures can replace any server response (status code, body, timing) to exercise
  specific client behaviour without a running JVM. The WebAuthn browser API
  (`navigator.credentials.create` / `.get`) is replaced with a fake authenticator that produces
  structurally valid CBOR/COSE artefacts. The tests need no Docker and no Chrome, and run with
  `npm test` from any IDE that can drive `vitest`.
- Mock-based unit tests remain appropriate when a failure mode is difficult to reproduce in the
  simulated environment (for example a network socket close mid-response or a CBOR encoding edge
  case) or when a very specific internal behaviour needs pinning. They are not the default.
- End-to-end tests (`PK_RUN_E2E=1`) provide the integration gate against the real Java server and a
  real browser. They gate CI but do not cover the full error-path matrix, which is the simulated
  environment's job.

The simulated environment stays flexible (tests can inject arbitrary server responses) but is not
production-hardened (no persistence, no rate limiting, no challenge store). Its only contract is
behavioural fidelity to the real server's happy path and well-defined error responses.

## Consequences

- Positive, seam coverage without infrastructure cost: the integration points between the fetch
  layer, encoding, and ceremony orchestration are exercised in every unit test run, and regressions
  at those seams surface immediately without Docker or a browser.
- Positive, controllable failure paths: server timeouts, 4xx/5xx responses, and authenticator
  failures can be injected deterministically, producing test coverage that is impractical to achieve
  against a real server.
- Positive, IDE-friendliness: `npm install` is the only prerequisite, and tests run and debug in any
  IDE with a Node.js adapter.
- Positive, loose coupling: tests assert observable outcomes (resolved or rejected promises,
  returned credential objects) rather than internal call sequences, so internal refactors do not
  require test rewrites.
- Negative, synchronisation between the fakes and the real implementations: the fake server and fake
  authenticator must stay in sync with the real ones. If the Java server changes a response shape,
  the simulated server must be updated, or tests silently diverge from production. The end-to-end
  suite is the backstop.
- Negative, the Node.js runtime is not a browser: subtle browser-specific behaviours (CSP,
  secure-context enforcement, platform authenticator UX) are not exercised by the simulated
  environment, and only the end-to-end suite can catch them.
- Constraint, end-to-end tests remain opt-in (`PK_RUN_E2E=1`) and do not cover the full failure
  matrix. They validate the happy path and critical flows against real infrastructure, and the unit
  suite owns error-path breadth.
