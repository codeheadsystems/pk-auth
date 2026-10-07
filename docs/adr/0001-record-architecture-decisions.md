# 1. Record architecture decisions

Date: 2026-05-12

## Status

Accepted.

## Context

pk-auth is a multi-module library project (per `docs/history/pk-auth-build-brief.md`) targeting Spring Boot, Dropwizard, and Micronaut. Decisions made in early phases — choice of WebAuthn library, persistence stack, DI strategy per framework, stateless JWT default, single-table DynamoDB design, and others — will be hard to reverse without breaking downstream consumers. We need a lightweight, durable record of these decisions, the context in which they were made, and the consequences they imply.

## Decision

Use Markdown Architecture Decision Records (ADRs) under `docs/adr/`, numbered sequentially starting from `0001`, in the Michael Nygard format:

- **Title** — short, imperative.
- **Date** — ISO date.
- **Status** — `Proposed` | `Accepted` | `Superseded by NNNN` | `Deprecated`.
- **Context** — the forces at play.
- **Decision** — what we are doing.
- **Consequences** — what follows from the decision, including downsides.

The placeholder ADRs already enumerated in the build brief (§5: `0002-webauthn4j-over-yubico`, `0003-jdbi-over-jpa`, `0004-dagger-for-dropwizard`, `0005-stateless-jwt-default`, `0006-userlookup-spi-not-owned`, `0007-dynamodb-local-vs-localstack`, `0008-dynamodb-single-table-design`) are reserved slots and will be written when the corresponding phase lands.

## Consequences

- Every non-trivial cross-module or cross-cutting decision lands as an ADR before or alongside the change that introduces it. Per `CONTRIBUTING.md`, new dependencies are justified in either a commit message or an ADR.
- ADRs are append-only: when a decision is reversed, a new ADR is added with status `Accepted` and the prior ADR is updated to `Superseded by NNNN`.
- Downside: this is process overhead. We accept the overhead for decisions that change public API, persistence schema, security posture, or cross-module contracts (per build brief §12.2). Method names, internal package layout, and similar reversible choices do not need an ADR.
