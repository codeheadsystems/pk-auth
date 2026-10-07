# 2. WebAuthn4J over Yubico java-webauthn-server

Date: 2026-05-13

## Status

Accepted.

## Context

pk-auth needs a JVM WebAuthn implementation that handles attestation and assertion validation, COSE
key parsing, and authenticator-data flag interpretation. Two mature options exist:

- WebAuthn4J (`com.webauthn4j:webauthn4j-core`) is actively maintained, has a JSON-first API, tracks
  the WebAuthn Level 3 spec including modern extensions (PRF, largeBlob), and has a Java 17+
  baseline. Spring Security's webauthn module uses it internally. Its licence is permissive (Apache
  2.0).
- Yubico's java-webauthn-server (`com.yubico:webauthn-server-core`) is older and stable, but its
  `CredentialRecord` and `CredentialRepository` abstractions are tightly coupled to specific
  persistence patterns. The lag since its last meaningful release exceeds WebAuthn4J's. Its licence
  is also Apache 2.0.

The brief (§3) names WebAuthn4J explicitly and forbids both `webauthn4j-spring-security` and
Yubico's library.

## Decision

Depend directly on `com.webauthn4j:webauthn4j-core`. pk-auth wraps WebAuthn4J's `WebAuthnManager` in
its own framework-neutral `PasskeyAuthenticationService` (Phase 2). WebAuthn4J types are absent from
the public API surface: `pk-auth-core` defines its own DTOs and result types so that:

1. Adapter modules and downstream consumers can be pinned to the pk-auth wire contract independent
   of the WebAuthn4J release cadence.
2. A future swap (if WebAuthn4J ever becomes unmaintained) does not break adopters.
3. Spring users who prefer Spring Security's own webauthn module retain the option to opt out (the
   brief §4.2 documents this).

## Consequences

- Positive: the library covers the latest WebAuthn features, including extensions the example apps
  will eventually demonstrate. The project is active and its maintainers are responsive.
- Positive: ceremony validation has a single source of truth; pk-auth maintains no CBOR or
  attestation-format code of its own.
- Negative: WebAuthn4J 0.31.x moves to Jackson 3 internally. This drove ADR 0009: the whole core
  standardises on Jackson 3 to avoid two Jackson lineages on the runtime classpath.
- Negative: WebAuthn4J's `CredentialRecord` and `Authenticator` types are not in pk-auth's public
  API, so pk-auth translates at the service boundary. The mapping cost is small and buys API
  stability.

## Open follow-ups

- Phase 2 will surface concrete WebAuthn4J failure-to-`*Result` mappings.
- A future ADR may revisit attestation metadata (MDS3) integration. WebAuthn4J supplies the hook,
  and pk-auth defers the implementation per brief §7.
