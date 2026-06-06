# 3. JDBI over JPA

Date: 2026-05-14

## Status

Accepted.

## Context

pk-auth needs a SQL persistence option for sites running Postgres. The mainstream JVM choices are:

- **JDBI 3** — thin SQL-builder-and-mapper layer over JDBC. No proxying, no lazy loading, no entity manager. Resource use is predictable; SQL is visible at the call site.
- **JPA (Hibernate / EclipseLink / OpenJPA)** — full ORM with managed entities, transactions, lazy associations, schema-from-annotations. Powerful, but introduces a vocabulary and a runtime cost pk-auth doesn't need.
- **Spring Data JPA / Spring Data JDBC** — repository abstractions on top of JPA / JDBC. Coupled to Spring; we want adapter-neutral SPIs.
- **MyBatis** — middle ground; XML/annotation-driven SQL with mapping. Less idiomatic than JDBI in modern Java.

The build brief is explicit (§3): "JDBI 3 + Flyway against PostgreSQL. **No Hibernate, no JPA, no Spring Data JPA, no Micronaut Data JPA.**" §6.6 reinforces.

## Decision

`pk-auth-persistence-jdbi` uses JDBI 3 with Flyway for migrations. Repository implementations write raw, parameterized SQL against the Phase 5 schema and translate rows to `CredentialRecord` / `ChallengeRecord` via hand-written `RowMapper`s. No annotations on the records; the persistence concern stays in the persistence module.

## Consequences

- **Positive — predictability.** Every query is visible. No magic SQL emitted by an ORM. The audit-friendliest stance for an auth-layer module.
- **Positive — minimal runtime surface.** pk-auth-persistence-jdbi adds only JDBI 3, the Postgres JDBC driver, HikariCP (connection pool), and slf4j-api as runtime dependencies; Flyway is implementation-scoped and used at startup.
- **Positive — no JPA-style entity-manager threading caveats.** Repository methods are stateless; the brief's "no reflection in hot paths" stance (§11) holds.
- **Negative — no automatic schema generation.** Every change to a `CredentialRecord` / `ChallengeRecord` field needs a new Flyway migration. We accept this — auth-data migrations should be deliberate.
- **Negative — no entity-graph fetch.** pk-auth's data is shallow (no relationships across repositories), so this is fine for now. If a future feature needs a join, we write it.

## Open follow-ups

- A `pk-auth-persistence-jpa` module is **explicitly excluded** for v0.x (brief §13). If demand surfaces post-1.0, a separate ADR will weigh adding it.
