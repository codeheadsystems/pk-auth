plugins {
    id("pkauth.java-conventions")
    id("pkauth.test-conventions")
    application
}

description = "pk-auth Dropwizard demo: single-page passkey + admin walkthrough."

tasks.named<JavaCompile>("compileJava") {
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

application {
    mainClass.set("com.codeheadsystems.pkauth.demo.dropwizard.DemoApplication")
}

dependencies {
    implementation(project(":pk-auth-dropwizard"))
    implementation(project(":pk-auth-core"))
    implementation(project(":pk-auth-jwt"))
    implementation(project(":pk-auth-admin-api"))
    implementation(project(":pk-auth-backup-codes"))
    implementation(project(":pk-auth-magic-link"))
    implementation(project(":pk-auth-otp"))
    implementation(project(":pk-auth-testkit"))

    implementation(libs.dropwizard.core)
    implementation(libs.dropwizard.auth)
    implementation(libs.dropwizard.assets)
    implementation(libs.slf4j.api)
    runtimeOnly(libs.logback.classic)

    compileOnly("com.google.errorprone:error_prone_annotations:2.50.0")
    testCompileOnly("com.google.errorprone:error_prone_annotations:2.50.0")

    testImplementation(libs.dropwizard.testing)
}

// Bundle the @pk-auth/passkeys-browser SDK so the demo's index page can import it as an ES
// module. The SDK's `dist/` is gitignored — the root task `:buildPasskeysBrowserSdk` invokes
// `npm ci && npm run build` to produce it before processResources copies the bundle.
val passkeysBrowserDist = rootProject.file("clients/passkeys-browser/dist")
tasks.named<Copy>("processResources") {
    dependsOn(rootProject.tasks.named("buildPasskeysBrowserSdk"))
    from(passkeysBrowserDist) {
        include("index.js", "index.js.map")
        into("assets/passkeys-browser")
    }
}

// The demo intentionally has no coverage gate (it's a runnable showcase, not a library).
// Tests that ship with it are smoke tests over the wire.

tasks.named<JavaExec>("run") {
    // The demo ships an embedded config; no YAML file required when started with `gradle run`.
    args = listOf("server")
    // Brief §11 — adapters target virtual-thread-friendly HTTP servers. Dropwizard uses Jetty.
}
