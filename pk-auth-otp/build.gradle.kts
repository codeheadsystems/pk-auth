plugins {
    id("pkauth.library-conventions")
    id("pkauth.test-conventions")
    id("pkauth.publish-conventions")
}

description = "pk-auth OTP: 6-digit SMS codes for phone verification flows."

tasks.named<JavaCompile>("compileJava") {
    options.compilerArgs.addAll(
        listOf("-Xlint:-requires-automatic", "-Xlint:-requires-transitive-automatic"),
    )
}

dependencies {
    api(project(":pk-auth-core"))
    implementation(libs.slf4j.api)

    testImplementation(project(":pk-auth-testkit"))
    testRuntimeOnly(libs.logback.classic)
}

tasks.named<JacocoCoverageVerification>("jacocoTestCoverageVerification") {
    violationRules {
        rule {
            limit {
                counter = "LINE"
                minimum = "0.70".toBigDecimal()
            }
            limit {
                counter = "BRANCH"
                minimum = "0.80".toBigDecimal()
            }
        }
    }
}

tasks.named("check") {
    dependsOn("jacocoTestCoverageVerification")
}
