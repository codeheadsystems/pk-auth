plugins {
    id("pkauth.library-conventions")
    id("pkauth.test-conventions")
    id("pkauth.publish-conventions")
}

description = "pk-auth testkit: FakeAuthenticator, in-memory SPIs, and fixtures for unit tests."

dependencies {
    api(project(":pk-auth-core"))
    // AccessTokenStore lives in pk-auth-jwt; in-memory impl + parity scenarios need it on the API
    // surface so downstream test code can drive both pk-auth-core and pk-auth-jwt SPIs.
    api(project(":pk-auth-jwt"))
    // RefreshTokenRepository SPI + RefreshTokenScenarios live with the testkit so the JDBI and
    // DynamoDB integration tests can drive the same parity scenarios.
    api(project(":pk-auth-refresh-tokens"))
    api(libs.bundles.jackson)
    api(libs.webauthn4j.core)
    // AssertJ on the api surface because CeremonyScenarios uses `assertThat`. Downstream
    // persistence modules drive these scenarios from their integration tests and inherit the
    // dependency without redeclaring it.
    api(libs.assertj.core)
    implementation(libs.caffeine)
    implementation(libs.slf4j.api)

    testRuntimeOnly(libs.logback.classic)
}
