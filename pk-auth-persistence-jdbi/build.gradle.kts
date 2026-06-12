plugins {
    id("pkauth.library-conventions")
    id("pkauth.test-conventions")
    id("pkauth.publish-conventions")
}

description = "pk-auth persistence: JDBI 3 + Flyway + Postgres implementations of the core SPIs."

tasks.named<JavaCompile>("compileJava") {
    options.compilerArgs.addAll(
        listOf("-Xlint:-requires-automatic", "-Xlint:-requires-transitive-automatic"),
    )
}

dependencies {
    api(project(":pk-auth-core"))
    // AccessTokenStore lives in pk-auth-jwt; JdbiAccessTokenStore implements it.
    api(project(":pk-auth-jwt"))
    // RefreshTokenRepository SPI; JdbiRefreshTokenRepository implements it.
    api(project(":pk-auth-refresh-tokens"))
    api(libs.jdbi.core)
    // JDBI's class files reference com.google.errorprone.annotations.concurrent.GuardedBy.
    // Without errorprone-annotations on the compile classpath, javac emits an annotation-not-found
    // warning that -Werror turns fatal. Pulled in compileOnly so we don't broadcast it as a
    // runtime dependency.
    compileOnly("com.google.errorprone:error_prone_annotations:2.50.0")
    testCompileOnly("com.google.errorprone:error_prone_annotations:2.50.0")
    implementation(libs.flyway.core)
    runtimeOnly(libs.flyway.postgres)
    runtimeOnly(libs.postgresql)
    implementation(libs.hikaricp)
    implementation(libs.slf4j.api)

    testImplementation(project(":pk-auth-testkit"))
    testImplementation(libs.testcontainers.junit.jupiter)
    testImplementation(libs.testcontainers.postgresql)
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
