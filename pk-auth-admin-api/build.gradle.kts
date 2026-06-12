plugins {
    id("pkauth.library-conventions")
    id("pkauth.test-conventions")
    id("pkauth.publish-conventions")
}

description = "pk-auth admin API: framework-neutral credential & account management service."

tasks.named<JavaCompile>("compileJava") {
    options.compilerArgs.addAll(
        listOf("-Xlint:-requires-automatic", "-Xlint:-requires-transitive-automatic"),
    )
}

dependencies {
    api(project(":pk-auth-core"))
    api(project(":pk-auth-backup-codes"))
    api(project(":pk-auth-magic-link"))
    api(project(":pk-auth-otp"))
    implementation(libs.slf4j.api)

    testImplementation(project(":pk-auth-testkit"))
    testImplementation(project(":pk-auth-jwt"))
    testRuntimeOnly(libs.logback.classic)
}

// Stricter ≥80% line bar than the pkauth.test-conventions baseline (LINE ≥0.70, BRANCH ≥0.55);
// the baseline branch floor applies via the convention.
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
