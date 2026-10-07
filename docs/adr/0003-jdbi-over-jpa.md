# 3. JDBI over JPA

Date: 2026-05-14

## Status

Accepted.

## Context

pk-auth needs a SQL persistence option for sites running Postgres. The mainstream JVM choices are:

- JDBI 3 is a thin SQL-builder-and-mapper layer over JDBC. It has no proxying, no lazy loading, and
  no entity manager. Resource use is predictable, and SQL is visible at the call site.
- JPA (Hibernate, EclipseLink, OpenJPA) is a full ORM with managed entities, transactions, lazy
  associations, and schema-from-annotations. It is powerful, but introduces a vocabulary and a
  runtime cost pk-auth does not need.
- Spring Data JPA and Spring Data JDBC are repository abstractions on top of JPA and JDBC. They are
  coupled to Spring, while pk-auth needs adapter-neutral SPIs.
- MyBatis is a middle ground, with XML- or annotation-driven SQL and mapping. It is less idiomatic
  than JDBI in modern Java.

The build brief is explicit (§3): "JDBI 3 + Flyway against PostgreSQL. No Hibernate, no JPA, no
Spring Data JPA, no Micronaut Data JPA." §6.6 repeats the constraint.

## Decision

`pk-auth-persistence-jdbi` uses JDBI 3 with Flyway for migrations. Repository implementations write
raw, parameterised SQL against the Phase 5 schema and translate rows to `CredentialRecord` /
`ChallengeRecord` via hand-written `RowMapper`s. No annotations on the records; the persistence
concern stays in the persistence module.

## Consequences

- Positive, predictability: every query is visible, and no ORM emits hidden SQL. This suits an
  auth-layer module that is subject to audit.
- Positive, minimal runtime surface: `pk-auth-persistence-jdbi` adds only JDBI 3, the Postgres JDBC
  driver, HikariCP (connection pool), and slf4j-api as runtime dependencies. Flyway is
  implementation-scoped and runs at startup.
- Positive, no JPA-style entity-manager threading caveats: repository methods are stateless, and the
  brief's "no reflection in hot paths" stance (§11) holds.
- Negative, no automatic schema generation: every change to a `CredentialRecord` or
  `ChallengeRecord` field needs a new Flyway migration. Each auth-data migration is an explicit
  step.
- Negative, no entity-graph fetch: pk-auth's data is shallow (no relationships across repositories),
  so the gap has no current effect. A future feature that needs a join writes it by hand.

## Open follow-ups

- A `pk-auth-persistence-jpa` module is excluded for v0.x (brief §13). If demand surfaces post-1.0,
  a separate ADR will weigh adding it.
