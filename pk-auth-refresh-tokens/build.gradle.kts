plugins {
    id("pkauth.library-conventions")
    id("pkauth.test-conventions")
    id("pkauth.publish-conventions")
}

description =
    "pk-auth refresh tokens: rotating opaque tokens with family-based replay defense."

tasks.named<JavaCompile>("compileJava") {
    options.compilerArgs.addAll(
        listOf("-Xlint:-requires-automatic", "-Xlint:-requires-transitive-automatic"),
    )
}

dependencies {
    api(project(":pk-auth-core"))
    // RotateResult.Success carries data the consumer needs to mint a fresh access token via
    // PkAuthJwtIssuer — exposing the JwtClaims-shaped projection on the API surface keeps
    // composability one import away.
    api(project(":pk-auth-jwt"))
    implementation(libs.slf4j.api)

    testImplementation(project(":pk-auth-testkit"))
    testRuntimeOnly(libs.logback.classic)
}

// Raises only BRANCH above the pkauth.test-conventions baseline (LINE ≥0.70, BRANCH ≥0.55):
// family-based replay defense is branch-heavy and already well-covered, so the bar is pinned near
// current.
tasks.named<JacocoCoverageVerification>("jacocoTestCoverageVerification") {
    violationRules {
        rule {
            limit {
                counter = "BRANCH"
                minimum = "0.80".toBigDecimal()
            }
        }
    }
}
