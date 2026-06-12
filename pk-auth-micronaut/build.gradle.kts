plugins {
    id("pkauth.library-conventions")
    id("pkauth.test-conventions")
    id("pkauth.publish-conventions")
}

description = "pk-auth Micronaut adapter: @Factory + ceremony controller + optional admin controller + JWT filter."

tasks.withType<JavaCompile>().configureEach {
    // Micronaut's annotation processor + Java 21 emit a noisy "No processor claimed any of these
    // annotations" warning at javac. The processor itself runs correctly; -Werror just elevates
    // the warning to fatal. Suppress `processing` lint on this module.
    options.compilerArgs.addAll(
        listOf(
            "-Xlint:-requires-automatic",
            "-Xlint:-requires-transitive-automatic",
            "-Xlint:-processing",
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

    // Admin API is optional at runtime — same contract as the Spring Boot starter and the
    // Dropwizard bundle. We compile against it so the @Factory adminService bean and the
    // PkAuthAdminController compile, but it is NOT a transitive runtime dependency. The factory
    // bean is gated with @Requires(classes = AdminService.class) and the controller with
    // @Requires(beans = AdminService.class), so a host that leaves pk-auth-admin-api off its
    // runtime classpath simply never mounts /auth/admin/** (Micronaut evaluates the requirement
    // on the lightweight BeanDefinitionReference before loading the bean, so an absent
    // AdminService class never triggers a NoClassDefFoundError).
    compileOnly(project(":pk-auth-admin-api"))

    api(libs.micronaut.context)
    api(libs.micronaut.http)
    api(libs.micronaut.http.server.netty)
    implementation(libs.micronaut.runtime)
    implementation(libs.micronaut.jackson.databind)
    implementation(libs.slf4j.api)

    // Micronaut's @Inject site references the JDBI errorprone @GuardedBy via the persistence
    // modules. Same trick as pk-auth-persistence-jdbi.
    compileOnly("com.google.errorprone:error_prone_annotations:2.50.0")
    testCompileOnly("com.google.errorprone:error_prone_annotations:2.50.0")

    annotationProcessor(libs.micronaut.inject.java)

    testImplementation(project(":pk-auth-testkit"))
    // Admin API is compileOnly in main; the adapter's admin tests exercise the controller, so it
    // must be present on the test runtime classpath.
    testImplementation(project(":pk-auth-admin-api"))
    testImplementation(libs.micronaut.http.client)
    testImplementation(libs.micronaut.test.junit5)
    testAnnotationProcessor(libs.micronaut.inject.java)
    testRuntimeOnly(libs.logback.classic)
}
