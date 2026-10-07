# 12. Micronaut 4 for the Micronaut adapter

Date: 2026-05-16

## Status

Accepted.

## Context

`pk-auth-micronaut` was written directly against Micronaut 4.x (the build catalog currently pins
`micronaut = "4.10.25"`). The decision to skip Micronaut 3 entirely was made at module creation:
Micronaut 3 reached end of maintenance during pk-auth's first development cycle, and adopters
starting new projects in 2026 are expected on Micronaut 4.

Unlike Spring Boot 4 (ADR 0011), Micronaut 4 has not moved to Jackson 3. The official
`micronaut-jackson-databind` integration still binds Jackson 2 (`com.fasterxml.jackson.databind`)
as Micronaut's framework path. pk-auth-core runs on Jackson 3 (ADR 0009), so the Micronaut adapter
sits on a Jackson-2/3 boundary similar to the Dropwizard adapter's. pk-auth's controllers exchange
Jackson 3 trees, but the Micronaut framework binds request/response DTOs through its own Jackson 2
mapper. `PkAuthJacksonBridge` (introduced for Dropwizard) is reused here.

## Decision

The `pk-auth-micronaut` adapter targets the latest released Micronaut 4.x. The same "track latest
within the current major" posture used by Dropwizard (ADR 0010) and Spring Boot (ADR 0011) applies:
Dependabot proposes the bump, the build resolves or fails fast, and the team decides per release.

Micronaut 5 (when it ships) is reassessed in its own follow-up ADR. The expected pivot is either
Jackson 3 alignment (eliminating the bridge) or a different framework-internal mapper, and either
may motivate adapter work.

## Consequences

- Pro: adopters on Micronaut 4.x, the current LTS line, get a starter that matches their framework
  version.
- Pro: the Micronaut adapter's stability posture aligns with Spring Boot and Dropwizard, so all
  three adapters follow the same rule and adopters can predict pk-auth's framework-version policy.
- Con: the Jackson 2/3 boundary remains in the Micronaut adapter. The bridge code is shared with
  Dropwizard, so the maintenance cost is not duplicated.
- Con: when Micronaut 5 lands, an additional ADR and code work are expected. No deprecation cycle
  is offered to adopters on Micronaut 3; the pre-1.0 release stance covers this.

## Open follow-ups

- Revisit if Micronaut publishes a Jackson 3 binding for 4.x, which would remove the bridge in the
  Micronaut adapter without waiting for a major.
