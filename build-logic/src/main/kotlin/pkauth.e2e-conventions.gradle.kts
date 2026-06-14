// E2E (Playwright) conventions for the example demos. Each demo carries a sibling `e2e/`
// Playwright project that drives the full passkey ceremony through Chrome's CDP virtual WebAuthn
// authenticator (see examples/<demo>/e2e/). This wires that suite into `check` as an OPT-IN task:
// it runs only when PK_RUN_E2E=1 (or -PrunE2e) is set, so the default local `check` and the
// existing CI `build` job stay fast and Chrome-free. The dedicated CI e2e jobs
// (.github/workflows/ci.yml) set the flag; the task itself provisions the Chrome channel via
// `npx playwright install` (adding --with-deps when PW_INSTALL_DEPS is set, as CI does).
plugins {
    java
}

// Every demo's webServer binds the same port (:8080), so two e2eTest tasks must never run at once.
// With org.gradle.parallel=true a root-level `PK_RUN_E2E=1 ./gradlew check` would otherwise run the
// sibling demos' suites concurrently and collide on the port. A shared build service with
// maxParallelUsages=1 serializes them across the whole build (registerIfAbsent dedupes by name, so
// all three demos share one lock). In CI each demo runs on its own isolated runner, so this lock is
// a no-op there — it only matters for single-machine multi-demo runs.
abstract class E2eServerLock : BuildService<BuildServiceParameters.None>

val e2eServerLock = gradle.sharedServices.registerIfAbsent(
    "pkauthE2eServerLock",
    E2eServerLock::class,
) {
    maxParallelUsages.set(1)
}

// Opt-in switch: PK_RUN_E2E=1 in the environment, or -PrunE2e on the command line. An explicitly
// set PK_RUN_E2E (even to a non-"1" value) wins over the property, so `PK_RUN_E2E=0` forces off.
// Resolved to a plain Boolean at configuration time (the env var / property become configuration
// cache inputs) so the wiring below captures no script reference — an `onlyIf { provider.get() }`
// closure would not be configuration-cache-serializable.
val runE2e: Boolean = providers.environmentVariable("PK_RUN_E2E").orNull
    ?.let { it == "1" }
    ?: providers.gradleProperty("runE2e").isPresent

val e2eDir = layout.projectDirectory.dir("e2e")

val e2eTest = tasks.register<Exec>("e2eTest") {
    group = "verification"
    description = "Runs the Playwright end-to-end suite for this demo (opt-in: set PK_RUN_E2E=1)."
    usesService(e2eServerLock) // serialize across demos — they share port :8080
    workingDir = e2eDir.asFile
    // `npm ci` pins deps to the committed lockfile. `playwright install` provisions the Chrome
    // channel the config pins (CDP virtual WebAuthn needs Google Chrome); --with-deps is added in
    // CI (PW_INSTALL_DEPS) to also install the OS libraries. The webServer in playwright.config.ts
    // boots this demo via the Gradle `run` task, so no separately-started server is needed.
    commandLine(
        "sh", "-c",
        "npm ci --no-audit --no-fund && " +
            "npx playwright install ${'$'}{PW_INSTALL_DEPS:+--with-deps} chrome && " +
            "npx playwright test",
    )
}

// Wire into `check` only when opted in, so a default `check` (local or the CI `build` job) neither
// depends on nor runs the suite. `./gradlew :examples:<demo>:e2eTest` still runs it on demand.
if (runE2e) {
    tasks.named("check") {
        dependsOn(e2eTest)
    }
}
