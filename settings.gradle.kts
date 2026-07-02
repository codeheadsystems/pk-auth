pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
    // Maven Central publishing via Sonatype Central Portal. The aggregation plugin is auto-applied
    // to subprojects with `maven-publish` — `./gradlew publishAggregationToCentralPortal` uploads
    // every signed publication to the Central Portal in a single bundle.
    id("com.gradleup.nmcp.settings") version "1.6.1"
}

rootProject.name = "pk-auth"

includeBuild("build-logic")

// Central Portal credentials. Set CENTRAL_PORTAL_USERNAME / CENTRAL_PORTAL_PASSWORD (a user token)
// in CI; locally these resolve from `~/.gradle/gradle.properties` (centralPortalUsername /
// centralPortalPassword) if present, so a fresh clone doesn't crash without env vars.
nmcpSettings {
    centralPortal {
        username = System.getenv("CENTRAL_PORTAL_USERNAME")
            ?: providers.gradleProperty("centralPortalUsername").orNull
        password = System.getenv("CENTRAL_PORTAL_PASSWORD")
            ?: providers.gradleProperty("centralPortalPassword").orNull
    }
}

// Resolve project version from an exact Git tag (vX.Y.Z[-suffix]) so a tagged build produces the
// release version without editing gradle.properties. Local builds and untagged HEADs fall through
// to the SNAPSHOT version pinned in gradle.properties.
gradle.beforeProject {
    val gitVersion = providers.exec {
        commandLine("git", "describe", "--tags", "--exact-match", "HEAD")
        isIgnoreExitValue = true
    }.standardOutput.asText.get().trim()

    if (gitVersion.startsWith("v")) {
        val match = Regex("^v(\\d+\\.\\d+\\.\\d+(-[a-zA-Z0-9.]+)?)$").matchEntire(gitVersion)
        if (match != null) {
            version = match.groupValues[1]
            logger.lifecycle("Using version from Git tag: $version")
        } else {
            logger.warn("Git tag '$gitVersion' does not match semantic versioning format (vX.Y.Z)")
        }
    }
}

// Subprojects are added phase by phase (see pk-auth-build-brief.md §10).
include("pk-auth-core")
include("pk-auth-jwt")
include("pk-auth-backup-codes")
include("pk-auth-magic-link")
include("pk-auth-otp")
include("pk-auth-refresh-tokens")
include("pk-auth-admin-api")
include("pk-auth-persistence-jdbi")
include("pk-auth-persistence-dynamodb")
include("pk-auth-testkit")
include("pk-auth-spring-boot-starter")
include("pk-auth-dropwizard")
include("pk-auth-micronaut")
include("examples:spring-boot-demo")
include("examples:dropwizard-demo")
include("examples:micronaut-demo")
