# Architecture Decision Records

This directory holds pk-auth's Architecture Decision Records in
[Nygard format](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions),
numbered sequentially. ADRs are append-only: when a decision is reversed, a new
ADR is added and the prior one is marked `Superseded by NNNN`. See
[ADR 0001](./0001-record-architecture-decisions.md) for the format itself.

| # | Status | Date | Title |
|---|---|---|---|
| [0001](./0001-record-architecture-decisions.md) | Accepted | 2026-05-12 | Record architecture decisions |
| [0002](./0002-webauthn4j-over-yubico.md) | Accepted | 2026-05-13 | WebAuthn4J over Yubico java-webauthn-server |
| [0003](./0003-jdbi-over-jpa.md) | Accepted | 2026-05-14 | JDBI over JPA |
| [0004](./0004-dagger-for-dropwizard.md) | Accepted | 2026-05-14 | Use Dagger 2 for the Dropwizard adapter's DI |
| [0005](./0005-stateless-jwt-default.md) | Accepted | 2026-05-14 | Stateless JWT as the default post-ceremony credential |
| [0006](./0006-userlookup-spi-not-owned.md) | Accepted | 2026-05-15 | `UserLookup` is an SPI, not an owned table |
| [0007](./0007-dynamodb-local-vs-localstack.md) | Accepted | 2026-05-14 | DynamoDB Local over LocalStack for integration tests |
| [0008](./0008-dynamodb-single-table-design.md) | Accepted | 2026-05-14 | DynamoDB single-table design for auth items, separate users table |
| [0009](./0009-jackson-3-over-jackson-2.md) | Accepted | 2026-05-13 | Jackson 3 (`tools.jackson`) over Jackson 2 (`com.fasterxml.jackson`) |
| [0010](./0010-dropwizard-track-latest.md) | Accepted | 2026-05-15 | Track latest Dropwizard rather than pin to 4.x |
| [0011](./0011-spring-boot-4.md) | Accepted | 2026-05-16 | Spring Boot 4 / Spring Security 7 for the Spring starter |
| [0012](./0012-micronaut-4.md) | Accepted | 2026-05-16 | Micronaut 4 for the Micronaut adapter |
| [0013](./0013-refresh-tokens-family-rotation.md) | Accepted | 2026-05-16 | Rotating refresh tokens with family-based replay detection |
| [0014](./0014-per-audience-ttl-policy.md) | Accepted | 2026-05-16 | Per-audience JWT TTL via a TokenTtlPolicy SPI |
| [0015](./0015-stateful-access-tokens.md) | Accepted | 2026-05-16 | Stateful access tokens via AccessTokenStore SPI |
| [0016](./0016-user-deletion-fan-out.md) | Accepted | 2026-05-16 | User deletion fan-out is sequential and best-effort |
| [0017](./0017-sonarqube-cloud-static-analysis.md) | Superseded by [0018](./0018-remove-sonarqube-cloud.md) | 2026-06-11 | SonarQube Cloud for static analysis and coverage tracking |
| [0018](./0018-remove-sonarqube-cloud.md) | Accepted | 2026-06-11 | Remove SonarQube Cloud; enforce coverage with native JaCoCo line + branch gates |
