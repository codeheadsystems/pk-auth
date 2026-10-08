# 11. Spring Boot 4 and Spring Security 7

Date: 2026-05-16

## Status

Accepted.

## Context

`pk-auth-spring-boot-starter` was originally written against Spring Boot 3.x and Spring Security 6.
Both projects shipped majors (Spring Boot 4.0, Spring Security 7.0) ahead of pk-auth's first
published release, and the build catalog moved to the new majors during early development
(`spring-boot = "4.0.6"`, `spring-security = "7.0.5"` in `gradle/libs.versions.toml`).

Two facts shaped the decision to ride the new majors rather than pin to the 3.x/6.x line:

1. Jackson 3 alignment. ADR 0009 standardised `pk-auth-core` on Jackson 3
   (`tools.jackson.databind`). Spring Boot 4 ships Jackson 3 natively, which removes the boundary
   translation work the Dropwizard adapter still needs (`PkAuthJacksonBridge`). Pinning to Spring
   Boot 3 would have required a second Jackson bridge or a permanent Jackson-2 carve-out in the
   Spring starter.

2. The pre-1.0 release stance. Per `docs/stability.md`, pk-auth is pre-1.0: adopters pin exact
   versions and review release notes between bumps. No support promise exists that would be cheaper
   to keep on the older Spring majors. The "track the latest framework major" posture is already the
   precedent for Dropwizard (ADR 0010).

The notable Spring Security 7 shift is the deprecation of `WebSecurityConfigurerAdapter` and the
move to a fully lambda-based, DSL-based `SecurityFilterChain` bean. `PkAuthWebAutoConfiguration`
already builds the chain that way, so adopting Security 7 changed nothing in the starter's public
config surface.

## Decision

The `pk-auth-spring-boot-starter` adapter tracks the latest released Spring Boot major. Current pins
are `spring-boot = 4.0.6` and `spring-security = 7.0.5`. Future majors are evaluated per release. If
the public surface the starter exposes (`PkAuthProperties`, `SecurityFilterChain` wiring,
`PkAuthJwtAuthenticationFilter`) compiles cleanly on the new line and the starter's tests pass, the
bump lands. Otherwise the bump waits behind an issue that names the breaking change.

## Consequences

- Pro: a single Jackson stack in the Spring starter's runtime (Jackson 3 in both pk-auth and
  Spring). No bridge module is needed.
- Pro: adopters on the latest Spring Boot 4.x see one consistent versioned starter rather than a
  back-ported variant.
- Con: adopters who must stay on Spring Boot 3 cannot use the published starter. The current
  pre-1.0 stance treats this as acceptable. If it becomes a blocker, a
  `pk-auth-spring-boot-3-starter` companion module is the fallback plan (no work scheduled).
- Con: when Spring Boot 5 lands, the "track the latest" stance commits the project to a follow-on
  bump rather than a long pin. The mitigation is the same as in ADR 0010: Dependabot proposes, the
  build either resolves cleanly or fails on a feature branch, and the team decides.

## Open follow-ups

- Document the Jackson alignment benefit in `docs/history/pk-auth-build-brief.md` §6.11 (the brief
  still references Spring Boot 3 in places).
