# 17. SonarQube Cloud for static analysis and coverage tracking

Date: 2026-06-11

## Status

Superseded by [ADR 0018](0018-remove-sonarqube-cloud.md).

## Context

pk-auth already gates quality at build time: Spotless (formatting and SPDX), Error Prone with strict
JSpecify null discipline, per-module JaCoCo coverage floors (≥80% on `pk-auth-core`, ≥70% on
adapters), and Stryker mutation testing on the browser SDK. What is missing is a trend view of the
JVM code: coverage over time, code smells, security hotspots, and duplication tracked across commits
rather than only pass/fail at HEAD.

The project needs a hosted dashboard that:

- ingests the JaCoCo XML the build already produces, so no new coverage machinery is needed;
- understands the multi-module Gradle build as one project;
- is free for a public/open-source repository;
- runs from CI rather than requiring a separate scan service that cannot see the build.

Options considered:

- SonarQube Cloud (formerly SonarCloud) is hosted, free for public repos, has a first-class Gradle
  scanner (`org.sonarqube`), auto-detects JaCoCo XML, and integrates with GitHub PR decoration. It
  needs no infrastructure to run.
- Self-hosted SonarQube Community Edition uses the same analyser, but the project would host and
  maintain a server and database. This is excessive for an open-source library with no owner for
  the operations.
- Codecov and Coveralls provide coverage trend only, with no static analysis, hotspots, or
  duplication. They are narrower than the requirement.

## Decision

Adopt SonarQube Cloud via the `org.sonarqube` Gradle plugin, driven from CI.

- The plugin (version pinned in `gradle/libs.versions.toml`) is applied to the root project only,
  and multi-module aggregation is built in. The `sonar` block in the root `build.gradle.kts` carries
  `projectKey`, `organization`, host URL, and `sonar.exclusions` (the example apps and the generated
  browser SDK `dist/`).
- Coverage is not reconfigured. The scanner auto-detects each module's
  `build/reports/jacoco/test/jacocoTestReport.xml`, already emitted by `pkauth.test-conventions`.
  The CI step runs `./gradlew build jacocoTestReport sonar`.
- Analysis runs as a dedicated `sonar` job in `ci.yml`, gated to pushes and same-repo PRs (fork PRs
  cannot read `SONAR_TOKEN`), with `fetch-depth: 0` so Sonar gets full SCM blame for new-code
  attribution.
- The analysis is CI-based, with Automatic Analysis turned off on the Sonar side, because Automatic
  Analysis cannot run the Gradle build or see JaCoCo coverage.

## Consequences

- Positive, trend visibility: coverage, code smells, security hotspots, and duplication are tracked
  per commit with a quality gate on new code, complementing (not replacing) the existing per-module
  JaCoCo floors.
- Positive, no new coverage plumbing: Sonar consumes the JaCoCo XML the build already generates.
- Negative, a configuration-cache caveat: the `sonar` task is not Gradle configuration-cache
  compatible, and `gradle.properties` enables the configuration cache globally. CI invokes the
  analysis with `--no-configuration-cache`, a documented and scoped exception rather than a global
  change.
- Negative, no analysis on fork PRs: GitHub withholds secrets from fork PRs, so the `sonar` job is
  skipped there. External contributors' branches are covered once merged to `main`, the standard
  trade-off for an open-source repo.
- Negative, a heavier CI job: the `sonar` job runs the full `build` (including the Docker-backed
  Testcontainers integration tests) so coverage exists when the scanner reads it. This is
  acceptable on `ubuntu-latest` and can be optimised later by sharing coverage artefacts with the
  existing `build` job.

## Open follow-ups

- To make the quality gate block merges, wire the Sonar status check into branch protection.
- If CI time becomes a concern, the `sonar` job can download JaCoCo artefacts from the `build` job
  instead of rebuilding.
