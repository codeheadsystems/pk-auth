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
    //
    // -XDaddTypeAnnotationsToSymbol=true is required by Error Prone 2.27+ on JDK 21 so that
    // type-use annotations (e.g. JSpecify's @Nullable) are visible on symbols at analysis time.
    // Without it Error Prone refuses to start. See
    // https://github.com/google/error-prone/issues/4011
    options.compilerArgs.addAll(
        listOf("-Xlint:all", "-parameters", "-XDaddTypeAnnotationsToSymbol=true"),
    )
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

// Spotless + google-java-format intermittently fails class loading
// (`NoClassDefFoundError com/google/common/collect/ImmutableCollection`) when its work is served
// from a Gradle cache instead of running fresh. This happens on BOTH cache pathways:
//   - the build cache, on a cached-output hit (already mitigated repo-wide via
//     `org.gradle.caching=false` in gradle.properties), and
//   - the configuration cache, on a cache-hit run that restores the task without re-initializing
//     the formatter's lazily-loaded Guava classes (e.g. a second `check` or a `clean check`).
// `outputs.cacheIf { false }` closes the first pathway per-task; marking the tasks not compatible
// with the configuration cache forces them to always run fresh, closing the second. The formatter
// itself is correct on a fresh run — this only removes the bad-cache-state pathways.
tasks.matching { it.name.startsWith("spotless") }.configureEach {
    outputs.cacheIf { false }
    notCompatibleWithConfigurationCache(
        "Spotless google-java-format lazily loads Guava classes that fail to initialize when the" +
            " task is restored from the configuration cache; must run fresh.",
    )
}
