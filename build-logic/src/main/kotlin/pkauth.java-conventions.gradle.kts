import net.ltgt.gradle.errorprone.errorprone

plugins {
    java
    id("com.diffplug.spotless")
    id("net.ltgt.errorprone")
}

val libs = the<org.gradle.accessors.dm.LibrariesForLibs>()

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(libs.versions.java.get())
    }
}

dependencies {
    compileOnly(libs.jspecify)
    errorprone(libs.build.errorprone.core)
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    // -Werror is intentionally omitted in Phase 0: build-logic compilation already runs with strict
    // settings, and adapter modules may need to fine-tune lints per-module. The brief calls for
    // -Xlint:all -Werror on production modules — that gets layered on in library-conventions where
    // we know it is safe.
    options.compilerArgs.addAll(listOf("-Xlint:all", "-parameters"))
    options.errorprone.disableWarningsInGeneratedCode = true
    // Default Error Prone check set, with one project-wide override:
    // pk-auth's wire contract is WebAuthn's, which is binary-heavy (challenge bytes, credential
    // ids, COSE-encoded public keys, signatures, …). Modeling those as `byte[]` record
    // components is intentional; each affected record overrides equals/hashCode to compare by
    // content, so the default-record equality pitfall ErrorProne is protecting against doesn't
    // apply. Suppress the check globally rather than annotating every record.
    options.errorprone.disable("ArrayRecordComponent")
}

spotless {
    java {
        target("src/**/*.java")
        googleJavaFormat(libs.versions.google.java.format.get())
        licenseHeader("// SPDX-License-Identifier: MIT")
        removeUnusedImports()
        trimTrailingWhitespace()
        endWithNewline()
    }
    kotlinGradle {
        target("*.gradle.kts")
        trimTrailingWhitespace()
        endWithNewline()
    }
}

tasks.named("check") {
    dependsOn("spotlessCheck")
}
