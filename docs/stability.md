# pk-auth Stability and Versioning

## Current status: 2.x

pk-auth is **post-1.0** as of the `v1.0.0` tag. The current development line is
**2.0.0-SNAPSHOT** (`gradle.properties` is authoritative); the 1.1, 1.2, and
1.3 releases have shipped. See [`CHANGELOG.md`](../CHANGELOG.md) for the
per-release delta.

Post-1.0, pk-auth follows [Semantic Versioning](https://semver.org/):

| Change type | Version bump |
|---|---|
| Backwards-compatible additions to SPIs or REST wire format | MINOR (1.x) |
| Breaking change to any SPI method signature, removal of a method, or breaking wire-format change | MAJOR (2.0, 3.0, …) |
| Bug fixes that do not alter the public API | PATCH (1.x.y) |

Configuration key renames or removals are treated as breaking changes and
require a MAJOR bump.

> **1.1 migration note (historical).** The 1.1.0 release carried a small
> number of *intentional* breaking SPI changes against 1.0 — the
> `CredentialRepository.deleteByUserHandle` / `OtpRepository.deleteByUserHandle`
> additions, the `JwtConfig.tokenTtl` → `JwtConfig.ttlPolicy` swap, and the
> `JwtConfig.audience` → `JwtConfig.defaultAudience` rename. These landed
> together at 1.1.0; see `CHANGELOG.md` for the migration notes. From
> 1.1.0 onward the SemVer contract above is binding.

Pin to an exact version in your build file and review the changelog before
upgrading:

```kotlin
// build.gradle.kts
implementation("com.codeheadsystems:pk-auth-core:1.x.y")
```

## SPI surfaces

The following interfaces are the **extension points** that host applications
implement. All are covered by the 1.x SemVer contract above.

| SPI interface | Module | Purpose |
|---|---|---|
| `CredentialRepository` | `pk-auth-core` | Store and retrieve WebAuthn credential records. 1.1.0 adds `deleteByUserHandle` (breaking — see `CHANGELOG.md`). |
| `UserLookup` | `pk-auth-core` | Resolve a username to an internal user handle |
| `ChallengeStore` | `pk-auth-core` | Issue and atomically consume ceremony challenges |
| `BackupCodeRepository` | `pk-auth-backup-codes` | Store and verify Argon2id-hashed backup codes |
| `OtpRepository` | `pk-auth-otp` | Store and verify time-limited OTP codes. 1.1.0 adds `deleteByUserHandle` (breaking — see `CHANGELOG.md`). |
| `EmailSender` | `pk-auth-magic-link` | Dispatch magic-link emails |
| `SmsSender` | `pk-auth-otp` | Dispatch phone OTP messages |
| `AccessTokenStore` | `pk-auth-jwt` *(1.1.0)* | Persist every issued JWT JTI for stateful (server-revocable) access tokens. Default `noop()` preserves stateless behaviour. See ADR 0015. |
| `RevocationCheck` | `pk-auth-jwt` | In-process deny-list for valid JWTs that should be rejected. Orthogonal to `AccessTokenStore`. |
| `TokenTtlPolicy` | `pk-auth-jwt` *(1.1.0)* | Per-audience access-token TTL dispatch. `TokenTtlPolicy.single(ttl)` and `.fixed(default, overrides)` cover the common cases. See ADR 0014. |
| `RefreshTokenRepository` | `pk-auth-refresh-tokens` *(1.1.0)* | Storage SPI for the rotating refresh-token primitive. The `rotateAtomically` method is contractually required to mark-used + insert-successor atomically. See ADR 0013. |
| `UserDeletionListener` | `pk-auth-core` *(1.1.0)* | Hook for the `UserDeletionService` fan-out; library-shipped listeners cover credentials, backup codes, OTPs, access tokens, and refresh tokens. See ADR 0016. |
| `ConsumedJtiStore` | `pk-auth-core` | Mark magic-link JTIs consumed across replicas; in-memory default ships as Caffeine cache |
| `CeremonyRateLimiter` | `pk-auth-core` | Per-IP / per-username throttle on WebAuthn `start*` / `finish*` endpoints; in-memory default ships |

## Configuration keys

All configuration lives under the `pkauth.*` prefix. Renamed keys will be kept
as deprecated aliases for at least one minor release before removal.

## Wire format (REST + TypeScript SDK)

The REST API shape (`/auth/**` routes) and the TypeScript SDK
(`@pk-auth/passkeys-browser`) are versioned together. Breaking REST changes
require a MAJOR bump, the same as SPI changes.
