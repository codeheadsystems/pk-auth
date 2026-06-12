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

// pkauth.test-conventions sets the baseline gate (LINE ≥0.70, BRANCH ≥0.55) for every library
// module. pk-auth-core is held to the stricter ≥80% line bar from the brief §11; the baseline
// branch floor applies via the convention.
tasks.named<JacocoCoverageVerification>("jacocoTestCoverageVerification") {
    violationRules {
        rule {
            limit {
                counter = "LINE"
                minimum = "0.80".toBigDecimal()
            }
        }
    }
}
