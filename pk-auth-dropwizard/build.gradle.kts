plugins {
    id("pkauth.library-conventions")
    id("pkauth.test-conventions")
    id("pkauth.publish-conventions")
}

description =
    "pk-auth Dropwizard 5 adapter: ConfiguredBundle, Jersey resources, JWT auth filter," +
        " and Dagger 2 wiring (see ADR 0004, ADR 0010)."

tasks.named<JavaCompile>("compileJava") {
    // Dropwizard 5 pulls a handful of automatic-module dependencies (jersey, jetty, …) which
    // would otherwise emit lint warnings that -Werror turns fatal. Mirrors the JDBI module.
    // -Xlint:-processing silences javac's "No processor claimed any of these annotations" hint
    // — Dagger only claims its own annotations, and JAX-RS/Jakarta annotations are processed by
    // the runtime, not at compile time.
    options.compilerArgs.addAll(
        listOf(
            "-Xlint:-requires-automatic",
            "-Xlint:-requires-transitive-automatic",
            "-Xlint:-processing",
        ),
    )
}

tasks.named<JavaCompile>("compileTestJava") {
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
    api(project(":pk-auth-refresh-tokens"))
    api(libs.dropwizard.core)
    api(libs.dropwizard.auth)
    api(libs.dagger)
    api(libs.jakarta.inject.api)

    // Optional admin-api wiring; the bundle registers AdminResource iff the module is present.
    compileOnly(project(":pk-auth-admin-api"))
    compileOnly(project(":pk-auth-backup-codes"))
    compileOnly(project(":pk-auth-magic-link"))
    compileOnly(project(":pk-auth-otp"))

    // Dropwizard's transitive Jersey/Jakarta dependencies surface annotations whose enclosing
    // packages reference com.google.errorprone.annotations.* — same pattern as the JDBI module.
    compileOnly("com.google.errorprone:error_prone_annotations:2.50.0")
    testCompileOnly("com.google.errorprone:error_prone_annotations:2.50.0")

    implementation(libs.slf4j.api)

    annotationProcessor(libs.dagger.compiler)
    testAnnotationProcessor(libs.dagger.compiler)

    testImplementation(project(":pk-auth-testkit"))
    testImplementation(project(":pk-auth-admin-api"))
    testImplementation(project(":pk-auth-backup-codes"))
    testImplementation(project(":pk-auth-magic-link"))
    testImplementation(project(":pk-auth-otp"))
    testImplementation(libs.dropwizard.testing)
    testRuntimeOnly(libs.logback.classic)
}

// Brief §11 adapter-tier coverage gate; Dagger-generated code is excluded from both the report
// and the verification rule.
tasks.named<JacocoReport>("jacocoTestReport") {
    classDirectories.setFrom(
        files(classDirectories.files.map {
            fileTree(it) {
                exclude(
                    "com/codeheadsystems/pkauth/dropwizard/dagger/Dagger*",
                    "**/*_Factory.class",
                    "**/*_MembersInjector.class",
                    "**/*_Provide*Factory.class",
                )
            }
        }),
    )
}

tasks.named<JacocoCoverageVerification>("jacocoTestCoverageVerification") {
    classDirectories.setFrom(
        files(classDirectories.files.map {
            fileTree(it) {
                exclude(
                    "com/codeheadsystems/pkauth/dropwizard/dagger/Dagger*",
                    "**/*_Factory.class",
                    "**/*_MembersInjector.class",
                    "**/*_Provide*Factory.class",
                )
            }
        }),
    )
}
