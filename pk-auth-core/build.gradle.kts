plugins {
    id("pkauth.library-conventions")
    id("pkauth.test-conventions")
    id("pkauth.publish-conventions")
}

description = "pk-auth core: framework-neutral SPIs, DTOs, and ceremony service interface."

// Suppress the `requires-automatic` lint just for module-info compilation: Micrometer is the
// only automatic-module dependency, and we surface it as `requires static` so adopters don't
// pay for it at runtime. When Micrometer ships an explicit module-info we can drop this.
tasks.named<JavaCompile>("compileJava") {
    options.compilerArgs.addAll(listOf("-Xlint:-requires-automatic", "-Xlint:-requires-transitive-automatic"))
}

dependencies {
    api(libs.jspecify)
    api(libs.webauthn4j.core)
    api(libs.bundles.jackson)

    implementation(libs.caffeine)
    implementation(libs.slf4j.api)

    // Optional: adapter modules can wire a real MeterRegistry. The core falls back to a no-op
    // when Micrometer isn't on the runtime classpath.
    compileOnly(libs.micrometer.core)

    testImplementation(libs.micrometer.core)
    testRuntimeOnly(libs.logback.classic)
}

// Phase 1 establishes the ≥80% line-coverage gate called for in the brief §11. The default in
// pkauth.test-conventions is intentionally permissive; this override turns the bar on for
// pk-auth-core specifically.
tasks.named<JacocoCoverageVerification>("jacocoTestCoverageVerification") {
    violationRules {
        rule {
            limit {
                counter = "LINE"
                minimum = "0.80".toBigDecimal()
            }
            limit {
                counter = "BRANCH"
                minimum = "0.70".toBigDecimal()
            }
        }
    }
}

tasks.named("check") {
    dependsOn("jacocoTestCoverageVerification")
}
