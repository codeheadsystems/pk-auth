plugins {
    id("pkauth.library-conventions")
    id("pkauth.test-conventions")
    id("pkauth.publish-conventions")
}

description = "pk-auth Spring Boot starter: auto-configuration, security filters, ceremony controller."

tasks.named<JavaCompile>("compileJava") {
    // Spring Boot autoconfigure (and several of its transitives) is published as an automatic
    // module on JDK 21. -Werror would otherwise turn the resulting warnings fatal. The same
    // dispensation is used in pk-auth-persistence-jdbi / pk-auth-admin-api.
    options.compilerArgs.addAll(
        listOf(
            "-Xlint:-requires-automatic",
            "-Xlint:-requires-transitive-automatic",
            // Spring Boot's configuration-processor only fires on @ConfigurationProperties;
            // javac then emits a noisy "no processor claimed these annotations" warning for
            // every Spring stereotype on the source set. Silence the processing pseudo-warning
            // category to keep -Werror clean.
            "-Xlint:-processing",
            // AbstractAuthenticationToken implements Serializable; our subclasses hold
            // non-Serializable pk-auth value objects (UserHandle, JwtClaims). The class is never
            // intended to be persisted across JVMs, so the warning is irrelevant.
            "-Xlint:-serial",
        ),
    )
}

dependencies {
    api(project(":pk-auth-core"))
    api(project(":pk-auth-jwt"))
    api(project(":pk-auth-backup-codes"))
    api(project(":pk-auth-magic-link"))
    api(project(":pk-auth-otp"))
    api(project(":pk-auth-refresh-tokens"))

    // Admin API is optional from a runtime perspective; the autoconfigure block reads it via
    // @ConditionalOnClass. We still depend on it `compileOnly` so the controller class compiles.
    compileOnly(project(":pk-auth-admin-api"))

    // The testkit ships small, framework-neutral InMemoryX implementations of every SPI.
    // The starter exposes those as conditional default beans so a host app can boot without
    // wiring persistence. Host apps that want a real backend declare their own bean and the
    // testkit defaults silently step aside (see PkAuthAutoConfiguration #ConditionalOnMissingBean).
    api(project(":pk-auth-testkit"))

    // Persistence modules are optional. The autoconfigure prefers JDBI when both are present.
    compileOnly(project(":pk-auth-persistence-jdbi"))
    compileOnly(project(":pk-auth-persistence-dynamodb"))

    implementation(libs.spring.boot.autoconfigure)
    implementation(libs.spring.boot.starter)
    implementation(libs.spring.boot.starter.web)
    implementation(libs.spring.boot.starter.security)
    implementation(libs.slf4j.api)

    annotationProcessor(libs.spring.boot.configuration.processor)

    testImplementation(project(":pk-auth-testkit"))
    testImplementation(project(":pk-auth-admin-api"))
    // Persistence modules pulled in tests so the autoconfig classes can be exercised.
    testImplementation(project(":pk-auth-persistence-jdbi"))
    testImplementation(project(":pk-auth-persistence-dynamodb"))
    testImplementation(libs.spring.boot.starter.test)
    testImplementation(libs.spring.boot.webmvc.test)
    testImplementation(libs.spring.security.test)
    testImplementation(libs.h2)
    testRuntimeOnly(libs.logback.classic)
}
