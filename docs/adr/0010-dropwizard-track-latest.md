# 10. Track latest Dropwizard rather than pin to 4.x

Date: 2026-05-15

## Status

Accepted. Supersedes the 4.x pin in brief §6.11.

## Context

The original brief mandated Dropwizard 4.x. The reason was conservative: 5.x moved to Jetty 12,
Jersey 4, and Jakarta EE 10, and the Phase 9 adapter was written against 4.x. The Dependabot config
blocked semver-major bumps on `io.dropwizard:*` to keep accidental upgrades from breaking the build.

Two facts changed the calculus:

1. The adapter's Dropwizard 5 surface is clean. A spike on 5.0.1 compiled with no code changes. The
   public types the adapter consumes (`ConfiguredBundle`, `Bootstrap`, `Environment`,
   `AuthDynamicFeature`, `AuthValueFactoryProvider`, `AuthFilter`, `Authenticator`,
   `AuthenticationException`, `@Auth`) all kept their package addresses across the major. The
   transitive Jetty 11 to 12 and Jersey 3.1 to 4 churn lands behind Dropwizard's own facade and
   never reaches the adapter.

2. The framework refresh pattern is established. When Spring Boot 4 and Spring Security 7 shipped,
   the project treated them as a normal upgrade rather than a permanent pin (see git log for commit
   `7b59f01`). Applying the same posture to Dropwizard keeps the codebase contemporary with upstream
   without inviting surprise breaks: Dependabot proposes the bump, the build either resolves cleanly
   or fails fast on a feature branch, and the team decides per major.

Dropwizard 5 does not bring Jackson 3 alignment. It still ships its own Jackson 2 ObjectMapper
(`com.fasterxml.jackson.core`), so `PkAuthJacksonBridge` keeps translating between Dropwizard's
mapper and pk-auth-core's Jackson 3 types. That simplification waits for a future Dropwizard major.

## Decision

The `pk-auth-dropwizard` adapter tracks the latest released Dropwizard. The catalog pin is the
current latest (5.0.2 at this time). The Dependabot `io.dropwizard:* version-update:semver-major`
ignore rule has been removed, and future majors surface as PRs the same way every other dependency
does.

Brief §6.11 now reads "Targets the latest released Dropwizard" rather than "Targets Dropwizard
4.x."

## Consequences

- Pro: one fewer permanent pin to maintain. The codebase stays close to upstream and benefits from
  the Jersey and Jetty modernisation Dropwizard ships.
- Pro: a clear precedent (this ADR and the Spring Boot 4 commit) makes future framework refresh
  decisions repeatable.
- Con: Dependabot can propose a Dropwizard major that breaks `pk-auth-dropwizard`. The mitigation
  is per PR: the build fails, and the PR stays unmerged until someone updates the adapter or
  chooses to defer.
- Neutral: the Jackson 2 bridge stays in place. The brief and the class javadoc of
  `PkAuthJacksonBridge` document it, and this ADR is the canonical reason for not deleting it yet.
