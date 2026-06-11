# 17. SonarQube Cloud for static analysis and coverage tracking

Date: 2026-06-11

## Status

Accepted.

## Context

pk-auth already gates quality at build time: Spotless (formatting + SPDX), Error Prone with strict JSpecify null discipline, per-module JaCoCo coverage floors (≥80% on `pk-auth-core`, ≥70% on adapters), and Stryker mutation testing on the browser SDK. What's missing is a *trend* view of the JVM code — coverage over time, code smells, security hotspots, and duplication tracked across commits rather than only pass/fail at HEAD.

We want a hosted dashboard that:

- ingests the JaCoCo XML we already produce, so no new coverage machinery is needed;
- understands the multi-module Gradle build as one project;
- is free for a public/open-source repository;
- runs from CI rather than requiring a separate scan service that can't see our build.

Options considered:

- **SonarQube Cloud (formerly SonarCloud)** — hosted, free for public repos, first-class Gradle scanner (`org.sonarqube`), auto-detects JaCoCo XML, integrates with GitHub PR decoration. No infrastructure to run.
- **Self-hosted SonarQube Community Edition** — same analyzer, but we'd host and maintain a server + database. Overkill for an open-source library; nobody owns the ops.
- **Codecov / Coveralls** — coverage trend only; no static analysis, hotspots, or duplication. Narrower than what we want.

## Decision

Adopt **SonarQube Cloud** via the `org.sonarqube` Gradle plugin, driven from CI.

- The plugin (version pinned in `gradle/libs.versions.toml`) is applied to the **root** project only; multi-module aggregation is built in. The `sonar` block in the root `build.gradle.kts` carries `projectKey`, `organization`, host URL, and `sonar.exclusions` (the example apps and the generated browser SDK `dist/`).
- Coverage is **not** reconfigured — the scanner auto-detects each module's `build/reports/jacoco/test/jacocoTestReport.xml`, already emitted by `pkauth.test-conventions`. The CI step runs `./gradlew build jacocoTestReport sonar`.
- Analysis runs as a dedicated `sonar` job in `ci.yml`, gated to pushes and same-repo PRs (fork PRs can't read `SONAR_TOKEN`), with `fetch-depth: 0` so Sonar gets full SCM blame for new-code attribution.
- We use **CI-based analysis**, with Automatic Analysis turned off on the Sonar side — Automatic can't run our Gradle build or see JaCoCo coverage.

## Consequences

- **Positive — trend visibility.** Coverage, code smells, security hotspots, and duplication are tracked per commit with a quality gate on *new code*, complementing (not replacing) the existing per-module JaCoCo floors.
- **Positive — no new coverage plumbing.** Sonar consumes the JaCoCo XML we already generate.
- **Negative — config cache caveat.** The `sonar` task is not Gradle configuration-cache compatible, and `gradle.properties` enables the config cache globally. CI invokes the analysis with `--no-configuration-cache`; this is a documented, scoped exception, not a global change.
- **Negative — fork PRs get no analysis.** GitHub withholds secrets from fork PRs, so the `sonar` job is skipped there. External contributors' branches are covered once merged to `main`; the standard trade-off for an open-source repo.
- **Negative — heavier CI job.** The `sonar` job runs the full `build` (including the Docker-backed Testcontainers integration tests) so coverage exists when the scanner reads it. Acceptable on `ubuntu-latest`; can be optimized later by sharing coverage artifacts with the existing `build` job.

## Open follow-ups

- If we want the quality gate to block merges, wire the Sonar status check into branch protection.
- If CI time becomes a concern, have the `sonar` job download JaCoCo artifacts from the `build` job instead of rebuilding.
