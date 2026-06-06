# 5. Stateless JWT as the default post-ceremony credential

Date: 2026-05-14

## Status

Accepted.

## Context

A successful WebAuthn ceremony (registration or assertion) needs to leave the caller
with something it can present on the next HTTP request. The two mainstream JVM choices are:

- **A framework-native HTTP session** (Spring's `HttpSession`, Dropwizard's optional Jetty
  session, Micronaut's session module). Server-side state; the cookie carries an opaque
  session id.
- **A signed, short-TTL JWT** issued by `pk-auth-jwt` (HS256 by default, ES256 when key
  rotation matters). Stateless; the bearer carries the claims.

The build brief is explicit (§4.4): "A successful passkey ceremony issues a signed JWT
via `pk-auth-jwt`. No HTTP session is required. Adapters MAY bridge to framework-native
sessions for users who want that, but the default is stateless JWT." This ADR records
the why.

pk-auth's deployment surface — three framework adapters (Spring Boot, Dropwizard,
Micronaut), two persistence backends (Postgres, DynamoDB), and a single TypeScript SDK
that talks to all of them — makes a session-affinity story expensive: a session store
would need its own adapter per persistence backend (`SessionStore` SPI, `JdbiSessionStore`,
`DynamoDbSessionStore`), its own TTL machinery, its own clustering story for the
adapter-specific session managers, and a uniform extraction path that every demo app
re-wires. A JWT defers all of that to the validator.

## Decision

The default post-ceremony credential is a signed JWT, scoped by `iss`/`aud`/`exp`/`nbf`,
keyed by the user's `UserHandle` in the `sub` claim, and tagged with the authentication
method in `pkauth.method`. The Spring Boot starter:

- Mints a JWT at the end of every successful `finishAuthentication` and returns it in the
  response body.
- Registers a JWT validation filter that produces a `JwtAuthenticationToken` for any
  request bearing a valid `Authorization: Bearer <token>`.
- Does **not** create an `HttpSession` and does not configure `SecurityContextRepository`
  to persist authentication between requests.

The Dropwizard and Micronaut adapters mirror this when they land in Phase 9 and Phase 10.

Adapters MAY expose an opt-in `sessionBridge` flag (the brief allows it). The default in
every shipped demo, however, is stateless JWT.

## Consequences

- **Positive — horizontal scaling is free.** Two app instances behind a load balancer
  validate the same JWT identically; no sticky sessions, no session-replication module.
- **Positive — uniform token across SDKs.** The TypeScript SDK in `clients/passkeys-browser`
  treats the post-ceremony token as a string regardless of which framework adapter served
  it. No framework-specific session cookie semantics leak into the browser layer.
- **Positive — adapter parity stays cheap.** Dropwizard and Micronaut implement the same
  "mint a token, register a validator filter" pattern. No need for three different session
  configurations.
- **Negative — revocation is harder.** A short TTL (default 1 hour) bounds the blast radius
  but doesn't eliminate it. A future denylist SPI on the `ChallengeStore` (or a sibling
  store) can plug this if we need true logout; the brief calls it out as a non-goal for v0.x.
  *(Shipped in 1.1.0 as the opt-in `AccessTokenStore` SPI — stateful, revocable-before-`exp`
  access tokens; the default stays the stateless no-op. See ADR 0015.)*
- **Negative — refresh-token machinery is not provided.** Hosts that need long-lived
  sessions must either accept re-authentication on TTL expiry or layer their own refresh
  flow on top. pk-auth's scope is the credential layer, not session management.
  *(Shipped in 1.1.0 as the `pk-auth-refresh-tokens` module — rotating refresh tokens with
  family-based replay defense. See ADR 0013.)*
- **Neutral — key rotation is a separate concern.** `JwtKeyset` already supports a current
  signing key plus a list of retired verification keys. Rotating the signing key invalidates
  no outstanding tokens; rotating it AND removing the retired key invalidates everything
  issued before the rotation.

## Open follow-ups

> **Resolved in 1.1.0.** Both deferred items below have since shipped. The stateless-JWT
> default in this ADR still stands — the new capabilities are opt-in and leave the default
> behavior unchanged.

- ~~A token-revocation SPI is deferred.~~ Shipped as `AccessTokenStore` (ADR 0015) — an
  allow-list (`record` / `exists` / `delete` / `deleteAllForUser` / `deleteExpiredBefore`)
  rather than the originally-sketched `RevokedTokenStore` deny-list. The validator consults
  it after signature validation; the default no-op store preserves stateless behavior.
- ~~Refresh-token issuance is out of scope.~~ Shipped as the `pk-auth-refresh-tokens` module
  (ADR 0013): rotating refresh tokens with family-based replay defense, exposed via
  `POST /auth/refresh`.
