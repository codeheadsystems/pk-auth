# 2. WebAuthn4J over Yubico java-webauthn-server

Date: 2026-05-13

## Status

Accepted.

## Context

pk-auth needs a JVM WebAuthn implementation that handles attestation and assertion validation, COSE key parsing, and authenticator-data flag interpretation. Two mature options exist:

- **WebAuthn4J** (`com.webauthn4j:webauthn4j-core`) — actively maintained, JSON-first API, tracks the WebAuthn Level 3 spec including modern extensions (PRF, largeBlob), Java 17+ baseline. Used by Spring Security's webauthn module under the hood. Permissive license (Apache 2.0).
- **Yubico's java-webauthn-server** (`com.yubico:webauthn-server-core`) — older, stable, but its `CredentialRecord` and `CredentialRepository` abstractions are tightly coupled to specific persistence patterns. Last meaningful release lag exceeds WebAuthn4J's. Also Apache 2.0.

The brief (§3) names WebAuthn4J explicitly and forbids both `webauthn4j-spring-security` and Yubico's library.

## Decision

Depend directly on `com.webauthn4j:webauthn4j-core`. pk-auth wraps WebAuthn4J's `WebAuthnManager` in our own framework-neutral `PasskeyAuthenticationService` (Phase 2). We do **not** expose WebAuthn4J types in our public API surface — `pk-auth-core` defines its own DTOs and result types so that:

1. Adapter modules and downstream consumers can be pinned to our wire contract independent of WebAuthn4J release cadence.
2. A future swap (if WebAuthn4J ever becomes unmaintained) does not break adopters.
3. Spring users who prefer Spring Security's own webauthn module retain the option to opt out — the brief §4.2 documents this.

## Consequences

- **Positive:** Latest WebAuthn coverage, including extensions our example apps will eventually demonstrate. Active project, responsive maintainers.
- **Positive:** Single source of truth for ceremony validation; no need to maintain our own CBOR / attestation-format code.
- **Negative:** WebAuthn4J 0.31.x cuts over to Jackson 3 internally. This drove ADR 0009 — we standardize the whole core on Jackson 3 to avoid two Jackson lineages on the runtime classpath.
- **Negative:** WebAuthn4J's `CredentialRecord` and `Authenticator` types are not in pk-auth's public API; we translate at the service boundary. Small mapping cost; pays for itself in API stability.

## Open follow-ups

- Phase 2 will surface concrete WebAuthn4J failure-to-`*Result` mappings.
- A future ADR may revisit attestation metadata (MDS3) integration — WebAuthn4J supplies the hook but pk-auth defers the implementation per brief §7.
