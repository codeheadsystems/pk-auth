# 18. Remove SonarQube Cloud; enforce coverage with native JaCoCo line + branch gates

Date: 2026-06-11

## Status

Accepted. Supersedes [ADR 0017](0017-sonarqube-cloud-static-analysis.md).

## Context

ADR 0017 adopted SonarQube Cloud for trend visibility and a new-code quality gate. In practice the
gate produced low-signal friction rather than insight:

- Its findings largely **duplicate tooling we already run at build time, more precisely**: null
  discipline is enforced by Error Prone + JSpecify, formatting/SPDX by Spotless, and test
  effectiveness by per-module JaCoCo floors plus Stryker mutation testing on the browser SDK.
- Several rules **conflicted with deliberate project conventions** — e.g. `S4449` demands JSR-305
  `javax.annotation.Nullable` while we standardize on JSpecify, and `S2583`/`S2589` flagged correct
  defensive null-guards on framework-injected parameters as dead code.
- The **new-code gate fired on attribution noise**: editing one line of an existing file surfaced a
  pre-existing, idiomatic pattern (`HttpResponse<?>` on a Micronaut `@Controller`) as a "new" issue,
  failing the gate over a non-defect.

Keeping the gate green required suppressions that litter the build with rule exclusions — paying
maintenance cost to satisfy a tool that told us less than the gates we already trust. The one thing
ADR 0017 genuinely wanted — **coverage tracked at line and branch level** — JaCoCo already provides
natively and offline.

## Decision

Remove the SonarQube Cloud integration and enforce coverage directly with JaCoCo.

- Drop the `org.sonarqube` Gradle plugin and its `sonar { }` block from the root build, the version
  catalog entry, the `sonar` CI job, and the SonarCloud README badges.
- Gate **both `LINE` and `BRANCH`** counters (previously line only), via a **hybrid** of one central
  baseline plus a few per-module overrides:
  - **Baseline** lives in `pkauth.test-conventions` and applies to every published library module:
    `LINE` ≥70%, `BRANCH` ≥55%. It is keyed off the `java-library` plugin (applied by
    `pkauth.library-conventions`) so it covers the libraries but **not** the `examples/*` demos,
    which apply `test-conventions` only for the JaCoCo report and are intentionally ungated.
  - **Overrides** stay in a module's own `build.gradle.kts` and raise only the limits above the
    baseline (Gradle enforces all rules, so an override never restates the floor): `pk-auth-core` /
    `pk-auth-jwt` / `pk-auth-admin-api` keep the ≥80% line bar from the brief §11; `pk-auth-jwt`,
    `pk-auth-backup-codes`, `pk-auth-otp`, and `pk-auth-refresh-tokens` pin `BRANCH` near their
    current (high) coverage. Every other module rides the baseline.
  - Branch floors are static — set below current measured coverage to lock in today's level and fail
    on regression; raise them as coverage improves. These gates run under `check`, which the `build`
    CI job already invokes.

## Consequences

- **Positive — no external service, no attribution noise.** Coverage is enforced deterministically
  from the build we already run; there is nothing to suppress.
- **Positive — branch coverage is now a hard gate**, not just a dashboard number, catching untested
  conditionals that line coverage alone misses.
- **Negative — no hosted trend dashboard.** We lose cross-commit graphs, duplication tracking, and
  the security-hotspot review surface. The first two were redundant with existing gates; if hotspot
  review is wanted later, prefer a tool that doesn't gate on new-code attribution.
- **Negative — branch floors are static.** They must be raised by hand as coverage improves;
  `jacocoTestReport` HTML shows current numbers when revising them.
