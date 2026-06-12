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
- Extend each module's existing `jacocoTestCoverageVerification` rule to gate **both `LINE` and
  `BRANCH`** counters (previously line only). Branch floors are set per module a few points below the
  current measured branch coverage, locking in today's level and failing the build on regression.
  Line floors are unchanged (≥80% on `pk-auth-core`/`pk-auth-jwt`/`pk-auth-admin-api`, ≥70%
  elsewhere). These gates run under `check`, which the `build` CI job already invokes.

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
