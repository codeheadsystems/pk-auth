# 18. Remove SonarQube Cloud; enforce coverage with native JaCoCo line + branch gates

Date: 2026-06-11

## Status

Accepted. Supersedes [ADR 0017](0017-sonarqube-cloud-static-analysis.md).

## Context

ADR 0017 adopted SonarQube Cloud for trend visibility and a new-code quality gate. In practice the
gate produced low-signal friction rather than insight:

- Its findings largely duplicate tooling already run at build time, more precisely: Error Prone and
  JSpecify enforce null discipline, Spotless enforces formatting and SPDX headers, and per-module
  JaCoCo floors plus Stryker mutation testing on the browser SDK enforce test effectiveness.
- Several rules conflicted with project conventions. For example, `S4449` demands JSR-305
  `javax.annotation.Nullable` while the project standardises on JSpecify, and `S2583` and `S2589`
  flagged correct defensive null-guards on framework-injected parameters as dead code.
- The new-code gate fired on attribution noise. Editing one line of an existing file surfaced a
  pre-existing, idiomatic pattern (`HttpResponse<?>` on a Micronaut `@Controller`) as a "new" issue
  and failed the gate over a non-defect.

Keeping the gate green required suppressions that litter the build with rule exclusions, a
maintenance cost paid to satisfy a tool that reported less than the gates already in place. The one
thing ADR 0017 needed, coverage tracked at line and branch level, JaCoCo already provides natively
and offline.

## Decision

Remove the SonarQube Cloud integration and enforce coverage directly with JaCoCo.

- Drop the `org.sonarqube` Gradle plugin and its `sonar { }` block from the root build, the version
  catalog entry, the `sonar` CI job, and the SonarCloud README badges.
- Gate both `LINE` and `BRANCH` counters (previously line only), via a hybrid of one central
  baseline plus a few per-module overrides:
  - The baseline lives in `pkauth.test-conventions` and applies to every published library module:
    `LINE` ≥70%, `BRANCH` ≥55%. It is keyed off the `java-library` plugin (applied by
    `pkauth.library-conventions`), so it covers the libraries but not the `examples/*` demos, which
    apply `test-conventions` only for the JaCoCo report and are ungated.
  - Overrides stay in a module's own `build.gradle.kts` and raise only the limits above the
    baseline (Gradle enforces all rules, so an override never restates the floor). `pk-auth-core`,
    `pk-auth-jwt`, and `pk-auth-admin-api` keep the ≥80% line bar from the brief §11.
    `pk-auth-jwt`, `pk-auth-backup-codes`, `pk-auth-otp`, and `pk-auth-refresh-tokens` pin `BRANCH`
    near their current (high) coverage. Every other module rides the baseline.
  - Branch floors are static: they are set below current measured coverage to lock in today's level
    and fail on regression, and they are raised as coverage improves. These gates run under
    `check`, which the `build` CI job already invokes.

## Consequences

- Positive, no external service and no attribution noise: coverage is enforced deterministically
  from the existing build, and there is nothing to suppress.
- Positive, branch coverage as a hard gate rather than a dashboard number: the gate catches
  untested conditionals that line coverage alone misses.
- Negative, no hosted trend dashboard: the project loses cross-commit graphs, duplication tracking,
  and the security-hotspot review surface. The first two were redundant with existing gates. If
  hotspot review is wanted later, a tool that does not gate on new-code attribution is preferable.
- Negative, static branch floors: they are raised by hand as coverage improves, and the
  `jacocoTestReport` HTML shows current numbers when revising them.
