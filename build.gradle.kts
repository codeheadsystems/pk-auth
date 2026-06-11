// Root build for pk-auth. Convention plugins live in build-logic/ and are applied per-module.
// The `base` plugin gives the root project the standard lifecycle tasks (build, check, clean,
// assemble).
plugins {
    base
    alias(libs.plugins.sonarqube)
}

// SonarQube Cloud analysis. Applied at the root for multi-module aggregation; the scanner
// auto-detects each module's JaCoCo XML report (build/reports/jacoco/test/jacocoTestReport.xml),
// produced by pkauth.test-conventions. Run via `./gradlew build jacocoTestReport sonar`.
// NOTE: the sonar task is not configuration-cache compatible, so CI invokes it with
// `--no-configuration-cache` (gradle.properties enables the config cache globally).
sonar {
    properties {
        property("sonar.projectKey", "codeheadsystems_pk-auth")
        property("sonar.organization", "codeheadsystems")
        property("sonar.host.url", "https://sonarcloud.io")
        property("sonar.exclusions", "examples/**,clients/passkeys-browser/dist/**")
    }
}

// Required for the nmcp aggregation plugin (auto-applied by `nmcp.settings` in settings.gradle.kts)
// to resolve its runtime dependencies. Subprojects keep their own repository declarations.
repositories {
    mavenCentral()
    gradlePluginPortal()
}

// `test` is a lifecycle task at the root so `./gradlew clean build test` aggregates `test`
// across all subprojects. Gradle's multi-project task expansion runs each subproject's own
// `test` task automatically; this root task is the aggregating entry point.
tasks.register("test") {
    group = "verification"
    description = "Lifecycle task that aggregates `test` across all subprojects."
    dependsOn(subprojects.map { it.tasks.matching { t -> t.name == "test" } })
}

// Root-level task that builds the @pk-auth/passkeys-browser SDK bundle into its `dist/` directory.
// The three example apps' processResources tasks depend on this so a fresh clone produces the
// bundle without a manual npm step. `dist/` is gitignored — the Gradle build is the source of
// truth, and tsup's inputs/outputs let Gradle skip the npm work on incremental rebuilds.
val passkeysBrowserDir = layout.projectDirectory.dir("clients/passkeys-browser")

tasks.register<Exec>("buildPasskeysBrowserSdk") {
    group = "build"
    description = "Builds the @pk-auth/passkeys-browser ESM/CJS bundles via npm + tsup."
    workingDir = passkeysBrowserDir.asFile
    // `npm ci` honors the committed package-lock.json for deterministic installs; `npm run build`
    // invokes tsup (see clients/passkeys-browser/tsup.config.ts).
    commandLine("sh", "-c", "npm ci --no-audit --no-fund && npm run build")
    inputs.dir(passkeysBrowserDir.dir("src"))
    inputs.file(passkeysBrowserDir.file("package.json"))
    inputs.file(passkeysBrowserDir.file("package-lock.json"))
    inputs.file(passkeysBrowserDir.file("tsup.config.ts"))
    inputs.file(passkeysBrowserDir.file("tsconfig.json"))
    outputs.dir(passkeysBrowserDir.dir("dist"))
}

