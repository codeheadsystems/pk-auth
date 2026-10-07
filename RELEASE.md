# Releasing pk-auth

The pk-auth libraries publish to Maven Central through GitHub Actions workflows, and the browser
SDK publishes to npm.

## What gets published

Every release publishes the same set of 13 artifacts, all under `com.codeheadsystems` and sharing
one version:

- `pk-auth-core`, `pk-auth-jwt`, `pk-auth-admin-api`
- `pk-auth-backup-codes`, `pk-auth-magic-link`, `pk-auth-otp`,
  `pk-auth-refresh-tokens`
- `pk-auth-persistence-jdbi`, `pk-auth-persistence-dynamodb`
- `pk-auth-testkit`
- `pk-auth-spring-boot-starter`, `pk-auth-dropwizard`, `pk-auth-micronaut`

The demo applications under `examples/` are not published.

The browser SDK `clients/passkeys-browser/` is published separately to npm as
`@pk-auth/passkeys-browser`. Its version tracks the server release it speaks to (the SDK and the
JVM artifacts share a version), so it is published as part of the same release. See
[Publishing the browser SDK to npm](#publishing-the-browser-sdk-to-npm) below. There is no CI
workflow for the npm publish yet; it is a manual step.

## Prerequisites (one-time)

The following secrets must exist on the GitHub repository. They are shared with
`hofmann-elimination` under the same `codeheadsystems` org, so a fresh fork needs them set once at
the org level.

| Secret                    | Purpose                                                              |
| ------------------------- | -------------------------------------------------------------------- |
| `CENTRAL_PORTAL_USERNAME` | Sonatype Central Portal user-token username                          |
| `CENTRAL_PORTAL_PASSWORD` | Sonatype Central Portal user-token password                          |
| `GPG_PRIVATE_KEY`         | Base64-encoded ASCII-armored private key used to sign artifacts      |
| `GPG_PASSPHRASE`          | Passphrase for the GPG key                                           |
| `GPG_KEY_ID`              | Long key id (or fingerprint) of the signing key                      |

The base64 form of the private key is generated locally with:

```sh
gpg --armor --export-secret-keys YOUR_KEY_ID | base64 -w 0
```

The signing key must be published to a public keyserver (for example `keys.openpgp.org`) so that
Central Portal can verify signatures.

## Release modes

Two GitHub Actions workflows are configured.

### A. Tagged release

The tagged release is the route for planned releases. A semver tag matching `vMAJOR.MINOR.PATCH`
(or `vMAJOR.MINOR.PATCH-suffix` for pre-releases) starts the `Tag Release to Maven Central`
workflow.

```sh
git switch main
git pull --ff-only
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

`settings.gradle.kts` reads the exact tag at build time and uses it as the project version, so
`gradle.properties` needs no edit beforehand.

A pre-release suffix (for example `v0.2.0-rc.1`) automatically marks the GitHub release as a
pre-release.

### B. Manual release

The manual release is a one-click patch bump for a quick patch release with no special version
planning. It runs from Actions → Manual Build Release to Maven Central → Run workflow. The workflow:

1. Reads the latest `vX.Y.Z` tag and increments the patch component.
2. Creates and pushes the new tag.
3. Runs the same publish and GitHub-release flow as the tagged path.

The tagged path (mode A) fits a minor or major bump, a pre-release suffix, or a version pinned in
the commit history before the workflow runs.

## What the workflow does

Both workflows perform the same steps:

1. Checkout with full history (`fetch-depth: 0`) so that `git describe` can see the tag.
2. Validation that the tag matches semver.
3. Setup of JDK 21 and Gradle.
4. Confirmation that Gradle's resolved version equals the tag's version.
5. `./gradlew clean build test --stacktrace`, the full build and test gate. A failure here aborts
   the release.
6. Import of the GPG key and configuration of non-interactive signing.
7. `./gradlew publishAggregationToCentralPortal`, which builds, signs, and uploads every module in
   a single bundle to the Central Portal.
8. Build of per-module `-sources.jar` and `-javadoc.jar` archives.
9. Creation of a GitHub release with all 13 module jars attached and a copy-paste
   `implementation(...)` snippet in the body.

## Verifying the release

After the workflow succeeds:

1. The GitHub release appears at <https://github.com/codeheadsystems/pk-auth/releases> with all
   jars attached.
2. Maven Central can take up to ~2 hours to index. The Central Portal dashboard at
   <https://central.sonatype.com/publishing/deployments> shows the status. The deployment moves
   through `VALIDATING → VALIDATED → PUBLISHING → PUBLISHED`.
3. The README badges (driven by `img.shields.io/maven-central/v/...`) refresh on their own once
   Central serves the new version, usually within an hour of publish completing.

## Local dry run

A release can be checked locally before tagging:

```sh
./gradlew clean build test                             # the gate the workflow uses
./gradlew publishMavenJavaPublicationToMavenLocal      # write jars to ~/.m2/repository
./gradlew tasks --group publishing                     # confirm the aggregation task is present
```

Local publish to Central Portal requires `~/.gradle/gradle.properties` to contain
`centralPortalUsername` / `centralPortalPassword` and a working `signing.gnupg.keyName`. Most
contributors do not need this; a pushed tag lets CI handle publishing.

## Troubleshooting

- Tag/version mismatch. The `Verify version matches tag` step fails when the `gradle.properties`
  version does not match the tag. Because `settings.gradle.kts` overrides the version from the tag,
  this normally fires only when the tag itself is malformed.
- GPG import fails. `GPG_PRIVATE_KEY` must be the base64 of the private key
  (`gpg --export-secret-keys`, not `--export`), encoded with `base64 -w 0` (single line, no wrap).
- Central Portal rejects the bundle. The dashboard's deployment detail page shows the cause. The
  most common cause is the signing key missing from a public keyserver; re-uploading to
  `keys.openpgp.org` and retrying resolves it.
- Artifact not visible after 2 hours. If the Central Portal deployment status shows `PUBLISHED`,
  the indexer is slow, and the artifacts are already downloadable via direct URL.
- `publishAggregationToCentralPortal` task missing. The `com.gradleup.nmcp.settings` plugin in
  `settings.gradle.kts` did not load. Confirming the plugin id and version, then re-running with
  `--refresh-dependencies`, resolves it.

## Publishing the browser SDK to npm

The browser SDK (`clients/passkeys-browser/`, package `@pk-auth/passkeys-browser`) is published to
npm manually after the Maven Central release for the same version has gone out. Its version must
match the pk-auth release version, because the SDK speaks the same wire contract as that server
release.

### Prerequisites (one-time)

- Node 22.22.2 or later, and npm (the same toolchain the Gradle SDK build uses).
- An npm account that is a member of the `@pk-auth` org/scope with publish rights. The package is
  public scoped (`publishConfig.access = "public"` is set in `package.json`, so no
  `--access public` flag is needed).
- Local authentication, done once with `npm login` (or by setting `NPM_TOKEN` / `~/.npmrc`).
  `npm whoami` confirms it.

### Steps

The steps run from `clients/passkeys-browser/`, with `X.Y.Z` replaced by the release version just
tagged for Maven Central (without the leading `v`).

```sh
cd clients/passkeys-browser

# 1. Match the SDK version to the server release (no git tag — the repo is
#    already tagged for the Maven release). This rewrites package.json's version.
npm version X.Y.Z --no-git-tag-version --allow-same-version

# 2. Clean install of the locked dependency tree.
npm ci

# 3. Dry run — verify the file list and resulting tarball before publishing.
#    `prepublishOnly` (typecheck + test + build) runs automatically on publish;
#    --dry-run exercises it without uploading.
npm publish --dry-run

# 4. Publish for real. `prepublishOnly` runs typecheck, tests, and the tsup
#    build, so dist/ is regenerated from source as part of the publish.
npm publish
```

`--no-git-tag-version` keeps the version bump from creating its own git tag, because the release is
already tagged (`vX.Y.Z`) for Maven Central. The SDK version is pinned to that same number so that
the two stay in lockstep.

> The committed `version` in `package.json` is the in-development line (for example
> `2.1.0-SNAPSHOT`), mirroring `gradle.properties`. `SNAPSHOT` is a valid semver prerelease
> identifier, so it is not published by accident, and step 1 always pins it to the concrete
> release version first. After publishing, `package.json` can stay at the published version or
> return to the `-SNAPSHOT` line on the development branch; either way, the next release re-pins it
> in step 1.

### Verifying the npm release

```sh
npm view @pk-auth/passkeys-browser version          # should report X.Y.Z
npm view @pk-auth/passkeys-browser dist-tags         # latest -> X.Y.Z
```

A pre-release (for example `X.Y.Z-rc.1`) is published under a dist-tag so that it does not become
`latest`:

```sh
npm version X.Y.Z-rc.1 --no-git-tag-version --allow-same-version
npm publish --tag next
```

### Rolling back an npm release

Like Maven Central, npm publishes are effectively immutable (unpublish is restricted and
discouraged). Recovery from a bad SDK release is a new patch version with the fix, not an
unpublish.

## Rolling back a release

Maven Central releases are immutable: a published version cannot be overwritten or deleted.
Recovery from a bad release is a new patch (or minor) release with the fix, followed by a consumer
update. Re-publishing the same version is not possible.
