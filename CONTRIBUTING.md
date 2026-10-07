# Contributing

## Working agreements

The architecture reference is [`DESIGN.md`](./DESIGN.md), with per-decision rationale in
[`docs/adr/`](./docs/adr/). The original bootstrap brief is archived at
[`docs/history/pk-auth-build-brief.md`](./docs/history/pk-auth-build-brief.md) for context only.

1. `main` stays releasable. Work lands as small pull requests against `main`. `./gradlew check`
   runs before pushing (CI runs the same gate), and user-visible changes are recorded under
   `[Unreleased]` in `CHANGELOG.md`.
2. Commits follow the conventional-commits format. Examples: `feat(core): ...`, `test(jdbi): ...`,
   `docs(adr): ...`, `build: ...`, `ci: ...`. Commits are small and atomic.
3. Non-trivial cross-module decisions get an ADR under `docs/adr/`, in Nygard format, numbered
   sequentially.
4. New libraries go through `gradle/libs.versions.toml` and are justified in the commit message or
   an ADR.
5. No `TODO` appears in main unless paired with a GitHub issue link.
6. Every Java source file carries the SPDX header `// SPDX-License-Identifier: MIT`. Spotless
   enforces it.
7. Public API carries `@since` tags. Every new or modified public element (class, record,
   interface, method, field, or sealed variant) gets an `@since X.Y.Z` Javadoc tag carrying the
   version it first ships in. For newly introduced surfaces, the current target is the in-flight
   version in `gradle.properties` (the `version` property, minus the `-SNAPSHOT` suffix). Existing
   surfaces keep the version they shipped with. A rename or signature change in a MAJOR bump
   updates the `@since` on the new shape. The policy applies across `pk-auth-core`,
   `pk-auth-admin-api`, `pk-auth-jwt`, `pk-auth-otp`, `pk-auth-magic-link`, `pk-auth-backup-codes`,
   `pk-auth-refresh-tokens`, and the three adapter modules.
8. Optimisation follows correctness and tests: correct, then tested, then fast.
9. Constructor-injection annotations differ by adapter. Spring and Micronaut detect a single
   non-default constructor automatically, so `@Autowired` and `@Inject` are not added in those
   adapters. The Dropwizard adapter is wired through Dagger 2, which requires `@Inject` on the
   injected constructor, so the annotation stays. The asymmetry follows the DI framework. New files
   in each adapter follow the conventions already present in that module.

## Build

```sh
./gradlew check
```

JDK 21 is required. Gradle's toolchain fetches one if needed.

## Running locally

[`GETTING_STARTED.md`](./GETTING_STARTED.md) holds the minimal adoption walkthrough and per-module
specifics.
