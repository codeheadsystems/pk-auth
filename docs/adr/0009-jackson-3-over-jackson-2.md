# 9. Jackson 3 (`tools.jackson`) over Jackson 2 (`com.fasterxml.jackson`)

Date: 2026-05-13

## Status

Accepted.

## Context

The build brief (§3) called for Jackson 2.x throughout the core. At Phase 1 we discovered that WebAuthn4J `0.31.x` — the version line the brief also names — migrated its internal CBOR/JSON parsing to Jackson 3 (`tools.jackson.databind`). Jackson 2 and Jackson 3 sit under different root packages and can coexist on the classpath, so three options were open:

1. Pin WebAuthn4J `0.30.3` (the last Jackson-2 release) and keep our core on Jackson 2.
2. Take WebAuthn4J `0.31.x` and ship two Jackson lineages — Jackson 2 for our DTOs, Jackson 3 transitively for WebAuthn4J.
3. Take WebAuthn4J `0.31.x` and migrate our DTOs to Jackson 3 (`tools.jackson`).

The constraints that made (3) the right call:

- The brief explicitly states we want **latest stable** versions everywhere. Forgoing a WebAuthn4J minor release to keep an older Jackson contradicts that priority.
- Shipping two Jackson stacks bloats the runtime classpath and creates a continuous "which one am I using?" tax for adapter authors, persistence modules, and host applications.
- Jackson 3 has been stable since `3.0.0` (May 2025). The `tools.jackson.core:jackson-databind:3.1.x` line is production-ready. The migration cost for our DTOs is contained to one file (`PkAuthObjectMappers`) plus the test imports.
- `com.fasterxml.jackson.core:jackson-annotations` is a separate jar from databind in Jackson 3 — it stays at the classical `com.fasterxml.jackson.annotation` package and works with both Jackson 2 and 3. Our DTO annotations (`@JsonInclude`, `@JsonProperty`) do not change.

## Decision

`pk-auth-core` standardizes on **Jackson 3** (`tools.jackson.databind 3.1.4`). The shared `ObjectMapper` factory uses the Jackson 3 `JsonMapper.builder()` flow, `ValueSerializer` / `ValueDeserializer`, and `changeDefaultPropertyInclusion(...)` for the NON_NULL output policy. We continue to use the classical `com.fasterxml.jackson.core:jackson-annotations 2.22` artifact for annotations.

Jackson 3's `tools.jackson.databind` bundles `java.time` and `Jdk8` datatype support directly into databind, so the separate `jackson-datatype-jsr310` and `jackson-datatype-jdk8` dependencies are no longer required.

## Consequences

- **Positive:** Single Jackson stack on the runtime classpath, matching WebAuthn4J 0.31.x.
- **Positive:** Pre-existing build brief §3 wording ("Jackson 2.x") is superseded by this ADR. Future ADRs that update the brief should reference this one.
- **Negative — Dropwizard interop risk.** Dropwizard 4 currently uses Jackson 2 internally for its own request/response binding. The Dropwizard adapter module (Phase 9) will need to:
  - Either run two `ObjectMapper` instances (one Jackson 2 for Dropwizard's framework path, one Jackson 3 for our pk-auth payloads), or
  - Wait for Dropwizard 5 to migrate to Jackson 3, or
  - Translate at the Jersey resource boundary.
  Phase 9 will explore this. Spring Boot 4 ships Jackson 3 natively; Micronaut 4 still bundles Jackson 2.
- **Negative:** Adapter authors familiar with Jackson 2 must learn the slightly different builder API. This is well documented upstream.
- **Negative:** Some Jackson ecosystem extensions (e.g., older Afterburner, certain Money/Joda modules) had not yet released Jackson 3 jars at the time of writing. None are on pk-auth's roadmap.

## Open follow-ups

- Phase 9 must produce a follow-up ADR documenting the concrete strategy chosen for Dropwizard's Jackson-2 internals. See [ADR 0010](0010-dropwizard-track-latest.md) for the Dropwizard versioning decision and the `PkAuthJacksonBridge` approach at the Jackson 2/3 boundary.
- The build brief `pk-auth-build-brief.md` §3 line "Jackson 2.x" is now historical — supersede in the next brief revision.
