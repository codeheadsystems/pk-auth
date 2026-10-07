plugins {
    id("pkauth.library-conventions")
    id("pkauth.test-conventions")
    id("pkauth.publish-conventions")
}

description = "pk-auth core: framework-neutral SPIs, DTOs, and ceremony service interface."

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
// module. pk-auth-core is held to a stricter ≥80% line bar; the baseline
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
