# 6. `UserLookup` as a host-implemented SPI

Date: 2026-05-15

## Status

Accepted.

## Context

pk-auth needs a stable mapping from `(username, email)` to `UserHandle` (the WebAuthn user
identifier, a stable, opaque byte string). Two designs were on the table:

1. Own the user table. pk-auth ships `pkauth_users (user_handle, username, email, display_name,
   created_at)`, owns the writes, and exposes a CRUD admin surface. Host apps query it for
   additional user data via FK.
2. Treat user lookup as an SPI. pk-auth declares the `UserLookup` interface (lookup by username,
   email, or handle, plus "find-or-create" semantics for first-passkey registration). The host app
   implements it against its own user store.

Option 1 is friendlier for greenfield demos but pushes pk-auth into the data-ownership business.
The host app inevitably has its own user table with columns pk-auth does not know about
(preferences, role bindings, billing IDs). Replicating that data, or making pk-auth's users
authoritative, locks the host into pk-auth's schema choices and creates a one-way migration trap.

Option 2 mirrors the rest of pk-auth's architecture, where every persistence concern is an SPI
(`CredentialStore`, `ChallengeStore`, `BackupCodeStore`, and so on). It also matches how IdPs such
as Keycloak and OIDC providers treat user federation: the identity provider owns "what is a
credential" and delegates "what is a user" to the system that already has answers.

## Decision

`UserLookup` is an SPI in `pk-auth-core`. The testkit ships an `InMemoryUserLookup` for demos and
tests; production hosts implement it against their existing user store. The pk-auth admin API and
ceremony flows route every "who is this?" call through the SPI.

The `UserHandle` mapping itself (handle to username) is also the host's responsibility. The host
returns the same `UserHandle` for the same `username` across calls; otherwise WebAuthn breaks. A
typical implementation stores `user_handle` as a `BYTEA` column on the host's `users` table with a
unique index.

## Consequences

- Pro: pk-auth never holds the user's PII. Host apps with strict data ownership requirements
  (HIPAA, GDPR, multi-tenant) can adopt it without negotiating schema.
- Pro: first-passkey registration ("does this username exist? if not, create a user with a fresh
  handle") is a single SPI method, atomic in the host's store and not split across two systems.
- Con: trivial demos need an in-memory `UserLookup`. The testkit ships one, and the example apps
  wire it.
- Con: a misimplemented `UserLookup` (returning different handles for the same username across
  calls) silently breaks WebAuthn. The SPI's contract documents this, and the testkit's contract
  tests assert it.
