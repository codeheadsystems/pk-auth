plugins {
    application
    id("pkauth.java-conventions")
    id("pkauth.e2e-conventions")
}

description = "pk-auth Micronaut demo app."

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.addAll(
        listOf(
            "-Xlint:-requires-automatic",
            "-Xlint:-requires-transitive-automatic",
            "-Xlint:-processing",
        ),
    )
}

application {
    mainClass.set("com.codeheadsystems.pkauth.demo.micronaut.MicronautDemoApplication")
}

dependencies {
    implementation(project(":pk-auth-micronaut"))
    // pk-auth-admin-api is compileOnly in the adapter (the admin surface is opt-in), so the demo —
    // which exercises the full admin walkthrough — declares it explicitly, the same way the
    // Spring Boot and Dropwizard demos do.
    implementation(project(":pk-auth-admin-api"))
    implementation(project(":pk-auth-testkit"))
    implementation(libs.micronaut.runtime)
    runtimeOnly(libs.logback.classic)

    annotationProcessor(libs.micronaut.inject.java)

    testImplementation(libs.micronaut.test.junit5)
    testImplementation(libs.micronaut.http.client)
    testImplementation(libs.bundles.test)
    testRuntimeOnly(libs.junit.platform.launcher)
    testAnnotationProcessor(libs.micronaut.inject.java)
}

// Bundle the @pk-auth/passkeys-browser SDK so the demo's index page can import it as an ES
// module. The SDK's `dist/` is gitignored — the root task `:buildPasskeysBrowserSdk` invokes
// `npm ci && npm run build` to produce it before processResources copies the bundle.
val passkeysBrowserDist = rootProject.file("clients/passkeys-browser/dist")
tasks.named<Copy>("processResources") {
    dependsOn(rootProject.tasks.named("buildPasskeysBrowserSdk"))
    from(passkeysBrowserDist) {
        include("index.js", "index.js.map")
        into("public/passkeys-browser")
    }
}

// Micronaut's nested @ConfigurationProperties binding does not propagate the
// pkauth.relying-party.* YAML keys into PkAuthConfiguration's nested RelyingParty in this
// adapter (the inner @ConfigurationProperties bean is created standalone but is not autowired
// back into the parent's field). The demo passes the values as system properties at
// startup so the browser sees `rp.id=localhost` instead of the library default `example.com`.
tasks.named<JavaExec>("run") {
    systemProperty("pkauth.relying-party.id", "localhost")
    systemProperty("pkauth.relying-party.name", "pk-auth Micronaut demo")
    systemProperty("pkauth.relying-party.origins[0]", "http://localhost:8080")
    systemProperty("pkauth.jwt.issuer", "pk-auth-micronaut-demo")
    systemProperty("pkauth.jwt.audience", "pk-auth-micronaut-demo-clients")
    systemProperty("pkauth.jwt.secret", "change-me-in-prod-use-a-32-byte-secret!!")
    // dev-mode is also set in application.yml, but — like the relying-party keys above — it must be
    // passed as a system property to reliably reach the bean conditions: the LoggingEmailSender /
    // LoggingSmsSender beans in PkAuthFactory are @Requires(property = "pkauth.dev-mode", value =
    // "true"), and without them the unconditional magicLinkService / otpService singletons fail to
    // inject EmailSender / SmsSender at request time (a 500 the e2e suite exercises).
    systemProperty("pkauth.dev-mode", "true")
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
