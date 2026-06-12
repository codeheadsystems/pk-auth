plugins {
    id("pkauth.library-conventions")
    id("pkauth.test-conventions")
    id("pkauth.publish-conventions")
}

description = "pk-auth persistence: AWS SDK v2 DynamoDB Enhanced implementations of the core SPIs."

tasks.named<JavaCompile>("compileJava") {
    options.compilerArgs.addAll(
        listOf("-Xlint:-requires-automatic", "-Xlint:-requires-transitive-automatic"),
    )
}

dependencies {
    api(project(":pk-auth-core"))
    // AccessTokenStore lives in pk-auth-jwt; DynamoDbAccessTokenStore implements it.
    api(project(":pk-auth-jwt"))
    // RefreshTokenRepository lives in pk-auth-refresh-tokens; DynamoDbRefreshTokenRepository
    // implements it.
    api(project(":pk-auth-refresh-tokens"))
    api(libs.aws.dynamodb)
    api(libs.aws.dynamodb.enhanced)
    implementation(libs.slf4j.api)

    testImplementation(project(":pk-auth-testkit"))
    testImplementation(libs.testcontainers.junit.jupiter)
    testImplementation(libs.testcontainers.core)
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
                minimum = "0.60".toBigDecimal()
            }
        }
    }
}

tasks.named("check") {
    dependsOn("jacocoTestCoverageVerification")
}
