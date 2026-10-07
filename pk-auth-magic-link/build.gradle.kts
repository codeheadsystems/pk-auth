plugins {
    id("pkauth.library-conventions")
    id("pkauth.test-conventions")
    id("pkauth.publish-conventions")
}

description = "pk-auth magic-link: JWT-based single-use email tokens for verification + login."

dependencies {
    api(project(":pk-auth-core"))
    api(project(":pk-auth-jwt"))
    implementation(libs.caffeine)
    implementation(libs.slf4j.api)

    testImplementation(project(":pk-auth-testkit"))
    testRuntimeOnly(libs.logback.classic)
}
