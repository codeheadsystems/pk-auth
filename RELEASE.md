# Releasing pk-auth

This document explains how to publish the pk-auth libraries to Maven Central
and the browser SDK to npm.

## What gets published

Every release publishes the same set of 13 artifacts, all under
`com.codeheadsystems` and sharing one version:

- `pk-auth-core`, `pk-auth-jwt`, `pk-auth-admin-api`
- `pk-auth-backup-codes`, `pk-auth-magic-link`, `pk-auth-otp`,
  `pk-auth-refresh-tokens`
- `pk-auth-persistence-jdbi`, `pk-auth-persistence-dynamodb`
- `pk-auth-testkit`
- `pk-auth-spring-boot-starter`, `pk-auth-dropwizard`, `pk-auth-micronaut`

The demo applications under `examples/` are intentionally **not** published.

Separately, the browser SDK `clients/passkeys-browser/` is published to **npm**
as `@pk-auth/passkeys-browser`. Its version tracks the server release it speaks
to (the SDK and the JVM artifacts share a version), so it is published as part of
the same release — see [Publishing the browser SDK to npm](#publishing-the-browser-sdk-to-npm)
below. There is no CI workflow for the npm publish yet; it is a manual step.

## Prerequisites (one-time)

These repository secrets must exist on the GitHub repo (they are shared with
`hofmann-elimination` under the same `codeheadsystems` org, so on a fresh fork
you only need to set them once at the org level):

| Secret                    | Purpose                                                              |
| ------------------------- | -------------------------------------------------------------------- |
| `CENTRAL_PORTAL_USERNAME` | Sonatype Central Portal user-token username                          |
| `CENTRAL_PORTAL_PASSWORD` | Sonatype Central Portal user-token password                          |
| `GPG_PRIVATE_KEY`         | Base64-encoded ASCII-armored private key used to sign artifacts      |
| `GPG_PASSPHRASE`          | Passphrase for the GPG key                                           |
| `GPG_KEY_ID`              | Long key id (or fingerprint) of the signing key                      |

To generate the base64 form of the private key locally:

```sh
gpg --armor --export-secret-keys YOUR_KEY_ID | base64 -w 0
```

The signing key must be published to a public keyserver (e.g.
`keys.openpgp.org`) so Central Portal can verify signatures.

## Release modes

Two GitHub Actions workflows are configured:

### A. Tagged release (preferred for planned releases)

Push a semver tag matching `vMAJOR.MINOR.PATCH` (or
`vMAJOR.MINOR.PATCH-suffix` for pre-releases) and the
`Tag Release to Maven Central` workflow takes over.

```sh
git switch main
git pull --ff-only
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

`settings.gradle.kts` reads the exact tag at build time and uses it as the
project version, so you do **not** need to edit `gradle.properties` first.

A pre-release suffix (e.g. `v0.2.0-rc.1`) automatically marks the GitHub
release as a pre-release.

### B. Manual release (one-click patch bump)

For a quick patch release with no special version planning, go to **Actions →
Manual Build Release to Maven Central → Run workflow**. The workflow:

1. Reads the latest `vX.Y.Z` tag and increments the patch component.
2. Creates and pushes the new tag.
3. Runs the same publish + GitHub-release flow as the tagged path.

Use the tagged path (mode A) when the release should be a minor or major bump,
when you want a pre-release suffix, or when you want the version pinned in the
commit history before the workflow runs.

## What the workflow does

Both workflows perform the same steps:

1. Checkout with full history (`fetch-depth: 0`) so `git describe` can see the
   tag.
2. Validate the tag matches semver.
3. Set up JDK 21 + Gradle.
4. Confirm Gradle's resolved version equals the tag's version.
5. `./gradlew clean build test --stacktrace` — full build and test gate; a
   failure here aborts the release.
6. Import the GPG key and configure non-interactive signing.
7. `./gradlew publishAggregationToCentralPortal` — builds, signs, and uploads
   every module in a single bundle to the Central Portal.
8. Build per-module `-sources.jar` and `-javadoc.jar` archives.
9. Create a GitHub release with all 13 module jars attached and a copy-paste
   `implementation(...)` snippet in the body.

## Verifying the release

After the workflow succeeds:

1. **GitHub release** appears at <https://github.com/codeheadsystems/pk-auth/releases>
   with all jars attached.
2. **Maven Central** can take up to ~2 hours to index. Check status at
   <https://central.sonatype.com/publishing/deployments> (Central Portal
   dashboard). The deployment moves through `VALIDATING → VALIDATED → PUBLISHING
   → PUBLISHED`.
3. **README badges** (driven by `img.shields.io/maven-central/v/...`) will
   refresh on their own once Central serves the new version — usually within
   an hour of publish completing.

## Local dry run

To sanity-check a release locally before tagging:

```sh
./gradlew clean build test                             # the gate the workflow uses
./gradlew publishMavenJavaPublicationToMavenLocal      # write jars to ~/.m2/repository
./gradlew tasks --group publishing                     # confirm the aggregation task is present
```

Local publish to Central Portal requires `~/.gradle/gradle.properties` to
contain `centralPortalUsername` / `centralPortalPassword` and a working
`signing.gnupg.keyName`. Most contributors do not need this — push a tag and
let CI handle it.

## Troubleshooting

- **Tag/version mismatch.** The `Verify version matches tag` step fails when
  `gradle.properties` version doesn't match the tag. Because
  `settings.gradle.kts` overrides version from the tag, this normally only
  fires when the tag itself is malformed.
- **GPG import fails.** Verify `GPG_PRIVATE_KEY` is base64 of the **private**
  key (`gpg --export-secret-keys`, not `--export`), encoded with `base64 -w 0`
  (single line, no wrap).
- **Central Portal rejects the bundle.** Check the dashboard's deployment
  detail page — the most common cause is the signing key not being on a public
  keyserver. Re-upload to `keys.openpgp.org` and retry.
- **Artifact not visible after 2 hours.** Re-check the Central Portal
  deployment status; if it shows `PUBLISHED`, the indexer is just slow —
  artifacts are already downloadable via direct URL.
- **`publishAggregationToCentralPortal` task missing.** Means the
  `com.gradleup.nmcp.settings` plugin in `settings.gradle.kts` did not load.
  Confirm the plugin id and version, then re-run with `--refresh-dependencies`.

## Publishing the browser SDK to npm

The browser SDK (`clients/passkeys-browser/`, package
`@pk-auth/passkeys-browser`) is published to npm manually after the Maven Central
release for the same version has gone out. Its version must match the pk-auth
release version (the SDK speaks the same wire contract as that server release).

### Prerequisites (one-time)

- **Node ≥ 20 + npm** (same toolchain the Gradle SDK build uses).
- An **npm account** that is a member of the `@pk-auth` org/scope with publish
  rights. The package is public scoped (`publishConfig.access = "public"` is set
  in `package.json`, so no `--access public` flag is needed).
- Authenticate locally once with `npm login` (or set `NPM_TOKEN` /
  `~/.npmrc`). Confirm with `npm whoami`.

### Steps

Run these from `clients/passkeys-browser/`. Replace `X.Y.Z` with the release
version you just tagged for Maven Central (without the leading `v`).

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

`--no-git-tag-version` is important: the version bump must **not** create its own
git tag, because the release is already tagged (`vX.Y.Z`) for Maven Central. Pin
the SDK version to that same number so the two stay in lockstep.

> The committed `version` in `package.json` is the in-development line
> (e.g. `2.0.0-SNAPSHOT`), mirroring `gradle.properties`. `SNAPSHOT` is a valid
> semver prerelease identifier, so it will not be published by accident — step 1
> always pins it to the concrete release version first. After publishing, you may
> leave `package.json` at the published version or restore the `-SNAPSHOT` line on
> the development branch; either way, the next release re-pins it in step 1.

### Verifying the npm release

```sh
npm view @pk-auth/passkeys-browser version          # should report X.Y.Z
npm view @pk-auth/passkeys-browser dist-tags         # latest -> X.Y.Z
```

For a **pre-release** (e.g. `X.Y.Z-rc.1`), publish under a dist-tag so it does
not become `latest`:

```sh
npm version X.Y.Z-rc.1 --no-git-tag-version --allow-same-version
npm publish --tag next
```

### Rolling back an npm release

Like Maven Central, npm publishes are effectively immutable (unpublish is
restricted and discouraged). To recover from a bad SDK release, publish a new
patch version with the fix rather than unpublishing.

## Rolling back a release

Maven Central releases are immutable — a published version cannot be
overwritten or deleted. To recover from a bad release, cut a new patch (or
minor) release with the fix and update consumers. Do not attempt to re-publish
the same version.
