plugins {
    id("pkauth.library-conventions")
    id("pkauth.test-conventions")
    id("pkauth.publish-conventions")
}

description = "pk-auth JWT issuance + validation built on Nimbus JOSE+JWT."

tasks.named<JavaCompile>("compileJava") {
    options.compilerArgs.addAll(
        listOf("-Xlint:-requires-automatic", "-Xlint:-requires-transitive-automatic"),
    )
}

dependencies {
    api(project(":pk-auth-core"))
    api(libs.nimbus.jose.jwt)
    implementation(libs.slf4j.api)

    testRuntimeOnly(libs.logback.classic)
}

tasks.named<JacocoCoverageVerification>("jacocoTestCoverageVerification") {
    violationRules {
        rule {
            limit {
                counter = "LINE"
                minimum = "0.80".toBigDecimal()
            }
            limit {
                counter = "BRANCH"
                minimum = "0.85".toBigDecimal()
            }
        }
    }
}

tasks.named("check") {
    dependsOn("jacocoTestCoverageVerification")
}
