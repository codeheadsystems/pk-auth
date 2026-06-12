# Contributing

## Working agreements

These mirror `pk-auth-build-brief.md` §12 — read that section for the full rationale.

1. **Phase discipline.** Complete the acceptance criteria for phase N (see brief §10) before starting phase N+1. Run `./gradlew check` between phases.
2. **Conventional commits.** Examples: `feat(core): ...`, `test(jdbi): ...`, `docs(adr): ...`, `build: ...`, `ci: ...`. Keep commits small and atomic.
3. **ADRs.** Non-trivial cross-module decisions get an ADR under `docs/adr/`, Nygard format. Number sequentially.
4. **Dependencies.** New libraries go through `gradle/libs.versions.toml` and are justified in the commit message or an ADR.
5. **No `TODO` in main** unless paired with a GitHub issue link.
6. **SPDX header** on every Java source file: `// SPDX-License-Identifier: MIT`. Spotless enforces this.
7. **`@since` tags on public API.** Every new or modified public element (class, record, interface, method, field, or sealed-variant) gets an `@since X.Y.Z` Javadoc tag carrying the version it first ships in. The current target is the in-flight version in `gradle.properties` (the `version` property, minus the `-SNAPSHOT` suffix) for newly introduced surfaces; existing surfaces keep the version they shipped with. When renaming a method or changing its signature in a MAJOR bump, update the `@since` on the new shape. The policy applies across `pk-auth-core`, `pk-auth-admin-api`, `pk-auth-jwt`, `pk-auth-otp`, `pk-auth-magic-link`, `pk-auth-backup-codes`, `pk-auth-refresh-tokens`, and the three adapter modules.
8. **Don't optimize prematurely.** Correct → tested → fast.
9. **Constructor-injection annotations.** Spring and Micronaut detect a single non-default constructor automatically; do not add `@Autowired` / `@Inject` in those adapters. Dropwizard's adapter is wired through Dagger 2, which requires `@Inject` on the injected constructor — keep the annotation. The asymmetry is by DI framework, not by style preference; new files in each adapter follow the conventions already present in that module.

## Build

```sh
./gradlew check
```

JDK 21 required (Gradle toolchain will fetch one if needed).

## Running locally

Module-level READMEs (added in each phase) document the "5-minute integration" snippet and per-module specifics.
