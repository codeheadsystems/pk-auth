# Phase 1 — `pk-auth-core` skeleton

Per the brief §10, Phase 1 lands the framework-neutral core as a *skeleton*: every public type that downstream modules will need exists with finalized signatures, but `DefaultPasskeyAuthenticationService` (the real WebAuthn4J wiring) is deferred to Phase 2. The one piece with real logic in Phase 1 is the Jackson `ObjectMapper` factory and its base64url codec.

**Acceptance (from §10):** All public types exist; the module compiles; >90% of types are covered by simple structural tests. Plus: ADR 0002 written. `./gradlew :pk-auth-core:check` green.

## Task list (in execution order)

### 1. Wire the module into Gradle
- Add `include("pk-auth-core")` to `settings.gradle.kts`.
- Create `pk-auth-core/build.gradle.kts` applying `pkauth.library-conventions` + `pkauth.test-conventions` + `pkauth.publish-conventions`.
- Dependencies (per brief §6.1 "No other runtime dependencies"):
  - `implementation` WebAuthn4J core, Jackson core + databind + datatype-jdk8 + datatype-jsr310, Caffeine, slf4j-api.
  - `compileOnly` Micrometer core (optional, NPE-safe no-op fallback in `metrics` package).
  - `compileOnly` JSpecify (already provided by `pkauth.java-conventions`).
  - `testImplementation` bundle from the test conventions; plus Logback for SLF4J binding in tests.
- Add new versions to `gradle/libs.versions.toml`: `webauthn4j` (latest stable, 0.31.x), `caffeine`, `micrometer`, `logback`, plus Jackson modules.

### 2. Package layout under `com.codeheadsystems.pkauth`
Match §6.1 exactly:
```
api, ceremony, credential, error, spi, config, json, metrics, internal
```
`internal` will be empty until Phase 2 — the brief still calls for the package to exist.

### 3. Core value types (`api` + `credential`)
- `UserHandle` — record wrapping `byte[]` with equals/hashCode based on content (default record equals is reference equality on arrays, so override). Static factory `UserHandle.of(byte[])` defensively copies; getter returns a defensive copy. Length validation: 1..64 bytes per WebAuthn spec.
- `ChallengeId` — record around `String` (UUID stringified). Factory plus a `random()` helper.
- `CredentialRecord` (in `credential` package) — record with fields per §4.5 + §6.7.1: `credentialId: byte[]`, `userHandle: UserHandle`, `publicKeyCose: byte[]`, `signCount: long`, `label: String`, `aaguid: byte[]` (or `UUID`), `transports: Set<String>`, `backupEligible: boolean`, `backupState: boolean`, `createdAt: Instant`, `lastUsedAt: Instant` (nullable).
- `CredentialMetadata` (in `credential` package) — read-only projection without `publicKeyCose` for endpoints that list credentials.
- `AuthenticatorData` — for Phase 1 this is a thin record holding the raw bytes + parsed flags (UP, UV, BE, BS, AT, ED). The brief lists it as the success-result type for registration; in Phase 2 we'll populate it from WebAuthn4J's parsed structure.

### 4. Sealed result types (`api`)
Literal copies of the §6.1 declarations:
- `RegistrationResult` with `Success`, `InvalidChallenge`, `OriginMismatch`, `AttestationRejected`, `DuplicateCredential`, `InvalidPayload`.
- `AssertionResult` with `Success`, `UnknownCredential`, `InvalidChallenge`, `OriginMismatch`, `CounterRegression`, `UserVerificationRequired`, `InvalidSignature`.

### 5. JSON request/response DTOs (`api`)
Records — field names mirror the WebAuthn JSON spec verbatim (`type`, `id`, `rawId`, `response`, `clientExtensionResults`, `authenticatorAttachment`). Binary fields are `byte[]` and (de)serialized as **base64url-no-padding** via the codec from task 9.
- `PublicKeyCredentialCreationOptionsJson` — what the server sends to start registration. RP info, user info, challenge, pubKeyCredParams, timeout, excludeCredentials, authenticatorSelection, attestation, extensions.
- `PublicKeyCredentialRequestOptionsJson` — what the server sends to start authentication. Challenge, timeout, rpId, allowCredentials, userVerification, extensions.
- `RegistrationResponseJson` — what the client returns. Contains `clientDataJSON`, `attestationObject`, `transports`.
- `AuthenticationResponseJson` — `clientDataJSON`, `authenticatorData`, `signature`, `userHandle`.
- `StartRegistrationRequest` — host-app input: `username`, `displayName` (nullable), `label` (nullable, credential label for the new passkey), `userVerification` preference (nullable → CeremonyConfig default).
- `FinishRegistrationRequest` — `username` or `userHandle` (one required), `label`, the `RegistrationResponseJson` payload.
- `StartAuthenticationRequest` — `username` (nullable, for usernameless flows), `userVerification` preference (nullable).
- `FinishAuthenticationRequest` — the `AuthenticationResponseJson` payload, plus the `ChallengeId` returned at start.

### 6. Service interface (`ceremony`)
- `PasskeyAuthenticationService` — interface with exactly the four methods from §6.1. Annotated `@NullMarked` (JSpecify) so the package-default is non-null and individual nullables are explicit.
- No implementation yet — Phase 2.

### 7. SPIs (`spi`)
Each in its own file:
- `CredentialRepository` — exact methods from §6.1.
- `UserLookup` + nested `UserView` record — exact methods from §6.1.
- `ChallengeStore` — exact methods from §6.1 (`put(ChallengeId, ChallengeRecord, Duration)`, `takeOnce(ChallengeId)`).
- `ChallengeRecord` (sibling type in `spi` so the contract is co-located) — record with `challenge: byte[]`, `purpose: Purpose` (enum: `REGISTRATION` | `ASSERTION`), `userHandle: UserHandle` (nullable for usernameless start), `expiresAt: Instant`.
- `ClockProvider` — functional interface returning `Instant`; default `system()` factory backed by `Clock.systemUTC()`.
- `OriginValidator` — functional interface, `boolean isAllowed(String origin)`. Default impl in `internal` (or `config`?) backed by an allow-list from `RelyingPartyConfig`.
- `AttestationTrustPolicy` — interface with `Decision evaluate(AttestationData)` returning `Trusted` / `Rejected(reason)`. Default impl `NoneAttestationPolicy` always returns Trusted (per §7 "attestation: none by default").

### 8. Configuration records (`config`)
- `RelyingPartyConfig` — `id` (RP ID, e.g. "example.com"), `name`, `origins: Set<String>`, `icon` (nullable, deprecated in spec but still common).
- `CeremonyConfig` — `challengeTtl: Duration` (default 5min), `userVerification: UserVerificationRequirement` enum, `residentKey: ResidentKeyRequirement` enum, `attestationConveyance: AttestationConveyance` enum, `counterRegression: CounterRegressionPolicy` enum (`REJECT` default, `WARN` opt-in per §7).
- All records implement compact constructors that null-check / validate.

### 9. Error hierarchy (`error`)
Exceptions that represent **programmer errors only** — the service maps WebAuthn failures to `*Result` variants, not exceptions (per brief Phase 2 note: "no exceptions cross the service boundary except programmer errors").
- `PkAuthException` — abstract base, extends `RuntimeException`.
- `ConfigurationException`, `IllegalStateError` — for misconfiguration detected at startup or mis-use of the service.
- Error-code enum `PkAuthErrorCode` with stable string codes for adapter modules to map to HTTP errors.

### 10. Jackson + base64url codec (`json`)
This is the one place real logic lives in Phase 1.
- `PkAuthObjectMappers` — factory returning a fully configured `ObjectMapper`:
  - `JavaTimeModule` + `Jdk8Module` registered.
  - `WRITE_DATES_AS_TIMESTAMPS` off (ISO-8601 strings).
  - `FAIL_ON_UNKNOWN_PROPERTIES` true on input.
  - `Include.NON_NULL` on output.
  - Custom `SimpleModule` registering a `byte[]` serializer/deserializer using **RFC 4648 §5 base64url, no padding**.
- `Base64Url` utility — small class wrapping `Base64.getUrlEncoder().withoutPadding()` / `Base64.getUrlDecoder()`, with explicit null guards.
- Document the wire-format choice in the `PkAuthObjectMappers` class javadoc.

### 11. Metrics shim (`metrics`)
- `Metrics` facade with `noop()` factory + a Micrometer-backed factory that's only constructed when `MeterRegistry` is on the classpath. Use `compileOnly` for Micrometer and a `ServiceLoader`/lazy-class-load pattern so the core remains runnable without Micrometer.
- Phase 1 only needs the counter/timer signatures; concrete usage lands in Phase 2.

### 12. Tests
Acceptance bar: ≥80% line coverage on `pk-auth-core` (per brief §11). Phase 1 strategy:
- **Structural tests** for every public record/sealed-interface type. AssertJ-driven, one test class per package proving instances can be constructed, equals/hashCode behave (especially for byte-array fields), and pattern-matching switches over sealed types compile.
- **Real tests** for the JSON codec: round-trip every `*Json` DTO; explicit base64url encoding tests against known vectors (empty array, single byte, length not divisible by 3 to ensure no padding leaks, leading-zero bytes, the WebAuthn-spec example challenge).
- **Null discipline tests** — compact constructors throw on null required fields.
- Enable the JaCoCo coverage gate at ≥80% line for `pk-auth-core` in `pk-auth-core/build.gradle.kts` (overriding the deferred default from `pkauth.test-conventions`).

### 13. ADR 0002
- `docs/adr/0002-webauthn4j-over-yubico.md` capturing the choice of `com.webauthn4j:webauthn4j-core` over Yubico's `java-webauthn-server`. Trade-offs: WebAuthn4J is more actively maintained on the latest spec (incl. PRF / largeBlob extensions), JSON-first API matches our wire format, no Spring coupling. Yubico is more entrenched but its CredentialRecord abstraction couples to specific persistence patterns we don't want in the core.

### 14. Verify
- `./gradlew :pk-auth-core:check` green.
- `./gradlew clean build test` green at root.
- Eyeball `./gradlew :pk-auth-core:jacocoTestReport` for the ≥80% bar.

## Clarifying questions

These are non-trivial and per §12.2 I'd like input rather than guess:

1. **`module-info.java` now or later?** The brief §11 calls for `module-info.java` exporting only `api`, `spi`, `config`. Adding it in Phase 1 enforces the surface from day one but adds friction for every internal split (and downstream consumers must be JPMS-aware). Defer to Phase 12 polish, or add now?

2. **`UserHandle` representation.** Three reasonable choices: (a) `record UserHandle(byte[] value)` with overridden equals/hashCode; (b) `record UserHandle(String value)` where value is base64url; (c) a final class wrapping bytes. The WebAuthn spec treats user handles as opaque 1-64 byte values. I lean toward (a) for fidelity, with serializers that base64url-encode at the JSON boundary. Confirm?

3. **WebAuthn4J in `api/` DTOs.** The brief says core depends on WebAuthn4J. Should our `*Json` DTOs use WebAuthn4J's own JSON types where they exist (re-exporting them via our package), or define our own records that map field-for-field? I lean toward defining our own — keeps the wire contract under our control and decouples adapter API stability from WebAuthn4J releases. Confirm?

4. **JSpecify scope.** `pkauth.java-conventions` already adds JSpecify on the `compileOnly` classpath. Annotate every public type with `@NullMarked` at the package level (one `package-info.java` per package), or sprinkle `@Nullable` site-by-site? Package-level `@NullMarked` is the brief's "Null discipline" stance read literally; I'll do that unless you object.

5. **Caffeine in core.** The brief lists Caffeine as a `pk-auth-core` dependency (§6.1) "no other runtime dependencies" but lists Caffeine among the allowed. Used where? Phase 1 doesn't need it yet — `InMemoryChallengeStore` lives in `pk-auth-testkit` (Phase 3). Confirm I should still add the dependency now to lock the wire, or defer until something actually consumes it?

6. **WebAuthn4J version pin.** Latest published as of 2026-05 is 0.31.x (per brief). Want me to use a specific patch (e.g. `0.31.0`), or take "latest 0.31.* at bootstrap"?

I'll wait for answers (or "go with your defaults") before writing code.
