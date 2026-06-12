plugins {
    java
    jacoco
}

val libs = the<org.gradle.accessors.dm.LibrariesForLibs>()

dependencies {
    "testImplementation"(platform("org.junit:junit-bom:${libs.versions.junit.jupiter.get()}"))
    "testImplementation"(libs.bundles.test)
    "testRuntimeOnly"(libs.junit.platform.launcher)
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

jacoco {
    // Pin the JaCoCo tooling version centrally so all modules report against the same engine.
    toolVersion = "0.8.12"
}

tasks.named<JacocoReport>("jacocoTestReport") {
    dependsOn(tasks.named("test"))
    reports {
        xml.required.set(true)
        html.required.set(true)
    }
}

tasks.named("check") {
    dependsOn(tasks.named("jacocoTestReport"))
}

// Baseline coverage gate for published library modules: LINE ≥70%, BRANCH ≥55%. Keyed off
// `java-library` (applied by pkauth.library-conventions) so it covers every library module but
// NOT the example apps, which apply test-conventions only for the JaCoCo report. A module may
// layer on a STRICTER rule in its own build.gradle.kts — Gradle enforces all rules, so a module
// override need only state the limits it raises, never restate this floor. Floors are static:
// bump them as coverage improves (jacocoTestReport's HTML shows current numbers).
plugins.withId("java-library") {
    tasks.named<JacocoCoverageVerification>("jacocoTestCoverageVerification") {
        violationRules {
            rule {
                limit {
                    counter = "LINE"
                    minimum = "0.70".toBigDecimal()
                }
                limit {
                    counter = "BRANCH"
                    minimum = "0.55".toBigDecimal()
                }
            }
        }
    }
    tasks.named("check") {
        dependsOn(tasks.named("jacocoTestCoverageVerification"))
    }
}
