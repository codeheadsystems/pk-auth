# pk-auth Threat Model

Scope: the pk-auth library, its three host adapters, and the wire contract its TS
SDK consumes. This document is **not** a deployment review — host applications still
own their TLS, network ingress, secrets-management, and authorization layers.

## Trust boundaries

```
┌───────────────────┐    HTTPS     ┌──────────────────────────────┐    SPI    ┌────────────┐
│   Browser / SPA   │ ───────────► │  pk-auth-adapter (Spring/    │ ───────►  │ Persistence│
│  + authenticator  │  WebAuthn    │  Dropwizard/Micronaut)       │           │ (JDBI /    │
│  (TPM / Touch ID  │  ceremony +  │  + pk-auth-core              │           │  DynamoDB) │
│   / hardware key) │  admin JSON  │                              │           └────────────┘
└───────────────────┘              └──────────────┬───────────────┘
                                                  │ logs
                                                  ▼
                                            SIEM / metrics
```

Boundaries cross-checked in this model:
1. **Browser ↔ adapter** — untrusted client. WebAuthn assertions and admin calls.
2. **Adapter ↔ persistence** — trusted; assumes operator runs Postgres/DynamoDB on
   a private network.
3. **Adapter ↔ secrets / KMS** — trusted; assumes the host injects credentials at
   boot.
4. **Source ↔ build/distribution pipeline** — semi-trusted. The artifacts pk-auth
   ships (Maven Central jars, the npm SDK) are only as trustworthy as the
   dependencies, build tools, and CI actions that produce them. See
   [Supply chain](#supply-chain).
5. **Human ↔ AI coding agent** — semi-trusted, and the most unusual boundary here.
   Substantially all of this code was written by an AI agent (see the README
   disclaimer). The agent is unaccountable, can be steered by the untrusted content
   it reads, and produces code faster than it can be deeply reviewed. Its output is
   gated only by human review. See [AI-authored code (provenance)](#ai-authored-code-provenance).

## STRIDE pass

### Spoofing

| Threat | Mitigation |
|---|---|
| Attacker forges a WebAuthn assertion | EC P-256/RSA signature verified against the registered public key via WebAuthn4J. Attestation conveyance is `NONE` by default; the default manager validates client data, origin, RP-ID, and assertion signatures but does NOT verify attestation statements. Hosts requiring attestation verification must opt into the strict manager (open finding). Counter regression catches some clone scenarios. |
| Attacker forges a JWT | HS256 signature with ≥ 32-byte secret. JWT verification enforces issuer, audience, expiry. |
| Attacker spoofs the relying party | RP ID and origin are checked server-side on every `finish` call — config-driven allow-list (`pkauth.relying-party.origins`). Cross-origin attempts are rejected with `origin_mismatch`. |
| Attacker reuses a backup code | Backup codes are Argon2id-hashed, single-use, and atomically claimed inside the SPI (`atomic claim or fail`). |
| Attacker presents a passkey the legitimate user never consciously authorized (lost/borrowed device with a key already enrolled, or a key with no user-presence factor) | User Verification defaults to `REQUIRED` (`CeremonyConfig.defaults()`), so WebAuthn4J enforces the asserted `flagUV` on every ceremony — the authenticator must prove a per-ceremony biometric or PIN, making the passkey a genuine "something you have **and** something you are/know" factor. Relaxing UV to `PREFERRED` or `DISCOURAGED` removes that guarantee: a present-but-unverified authenticator (mere user-presence, no biometric/PIN) is accepted, so a passkey degrades to "something you have" alone. Do not relax UV unless a deployment specifically needs UV-incapable hardware security keys, and understand it weakens the factor for everyone. |

### Tampering

| Threat | Mitigation |
|---|---|
| Tamper with the ceremony challenge | Challenges are server-issued, base64url, 32 random bytes. They are stored by `ChallengeId` with the associated `userHandle` recorded as a binding hint. The server enforces single-use consumption via `ChallengeStore.takeOnce` (atomic). |
| Tamper with the credential record | Credential ID + public key + counter + AAGUID are the only fields trusted by the verifier; the label/UA are operator-supplied and never participate in signature checks. |
| Tamper with the JWT in transit | HTTPS protects on the wire; JWT integrity is the HS256 MAC. |

### Repudiation

| Threat | Mitigation |
|---|---|
| User claims they did not authenticate | Every `finish` call logs the (`userHandle`, `credentialId`, `clientDataJSON.origin`, signing counter) tuple. The user's authenticator is the only entity capable of producing the assertion, so the audit trail is non-repudiable assuming the authenticator was not lost. |
| Operator denies revoking a credential | Admin operations log the acting `userHandle` and the target `credentialId`. Logs are append-only by convention; ship them to an immutable store. |

### Information Disclosure

| Threat | Mitigation |
|---|---|
| Disclose a credential's public key | Public keys are public. Their disclosure leaks no authentication material. |
| Disclose backup codes | Backup codes are returned plaintext **exactly once** at regeneration time. The server only retains Argon2id hashes. |
| Disclose magic-link tokens | A magic-link token is a signed single-use HS256 JWT (it carries a `pkauth.purpose` claim and is bound by the HS256 signature — not a random value stored hashed). It is never persisted: single-use is enforced by recording its JTI in a `ConsumedJtiStore` after redemption (JWT TTL 15m, consumed-JTI TTL 30m). The token only exists in the outbound email on the dispatcher path. Use a real email sender in production, and inject a shared `ConsumedJtiStore` for multi-replica deployments so a token can't be replayed across replicas. |
| Disclose JWT secret via logs | The starter never logs `pkauth.jwt.secret`. Other secrets (Argon2 pepper, RP origins) are bound only via env vars; do not echo them in `--debug` traces. |
| Enumerate usernames | `/auth/passkeys/registration/start` returns the same shape for any username (a fresh user handle is created); `/auth/passkeys/authentication/start` does not leak existence — it returns an `allowCredentials` list that an unknown user would receive empty. Avoid mounting routes that surface user existence (e.g. "/users/exists"). |

### Denial of Service

| Threat | Mitigation |
|---|---|
| Flood challenges | Challenges expire in 5 minutes by default and are stored by `ChallengeId`. pk-auth ships a `CeremonyRateLimiter` SPI (with an in-memory Caffeine-backed default) keyed on client IP and username; the `start*` / `finish*` endpoints short-circuit with `429 Retry-After` when the limiter denies. For multi-replica deployments, replace the default with a shared-store implementation. Heavy floods should still be filtered at the host's WAF / API gateway upstream of the adapter. |
| Hash-burn via repeated backup-code attempts | Backup codes are Argon2id-hashed (intentionally CPU-heavy), so a wrong code costs the attacker as much as a right one. The SPIs ship per-credential attempt counters; the magic-link and backup-code modules also ship per-user sliding-window rate limiters (in-memory defaults, override for multi-replica). |
| Brute-force / flood of OTP attempts | OTP codes are hashed with cheap HMAC-SHA256, **not** a CPU-heavy KDF — the 10^6 code space makes hash cost pointless, so the hash burn argument does **not** apply here. The defence is instead the per-credential attempt cap (default 5 verifies per code, enforced atomically in the repository) plus the per-(user, phone) send rate limiter (default 3 codes per 15-minute window). A wrong code is cheap to check but exhausts the cap quickly, and the rate limiter bounds how many fresh codes an attacker can mint. |
| Exhaust DB connections | Connection pooling is the host's responsibility. Recommend HikariCP for JDBI, the AWS SDK's default for DynamoDB. |

### Elevation of Privilege

| Threat | Mitigation |
|---|---|
| Use a backup code to register a new passkey for someone else's account | Backup codes authenticate the holder; the admin API still requires a JWT for the *acting* user, and rename/delete enforce `actor == owner`. A backup code alone cannot register a passkey on a different account — only re-bootstrap the existing one. |
| Use a stolen JWT to act as another user | JWTs are stateless and bearer; mitigation lives at the transport layer (HTTPS) and TTL (default 1 hour). Do not extend TTL without offsetting it with explicit revocation. Hosts requiring revocation (logout-all, account-disable) should implement the `RevocationCheck` SPI in `pk-auth-jwt`. |
| Delete every passkey to lock yourself in / out | `AdminService.deleteCredential` enforces a "last-credential guard" returning 409 Conflict when a delete would leave zero credentials. Backup codes remain available as a recovery path. |
| Cross-tenant access | The library is single-tenant. Multi-tenant deployments need an outer key (e.g. `tenantId`) routed at the host. pk-auth does not provide one. |

## Known limitations (in scope but not solved)

- **Attestation policy**: attestation conveyance is `NONE` by default. The default manager validates client data, origin, RP-ID, and assertion signatures but does NOT verify attestation statements. Hooks exist for MDS3 / metadata-service validation (`AttestationTrustPolicy`), but no MDS3 fetcher is bundled. Sites with FIDO attestation requirements must opt into the strict manager and implement their own MDS3 fetcher.
- **Counter regression**: rejected by default. Configurable to `warn` for sites that primarily
  expect counter-0 synced passkeys (Apple/Google ecosystems). Switching to `warn` weakens the
  clone-detection signal.
- **JWT revocation**: JWTs are valid until `exp` by default. The `RevocationCheck` SPI (added in `pk-auth-jwt`) allows hosts to implement revocation (logout-all, account-disable). Without it, accept the TTL bound on session length and prefer short TTLs.
- **Passkey export / migration**: not the library's concern. The user's authenticator owns the
  key material; pk-auth never sees it.

## Supply chain

pk-auth is a security library published to Maven Central and npm, so a compromise of
its build or its dependencies propagates directly into every downstream application —
a higher-leverage target than any single deployment. The dominant modern attack vector
is not a typosquat but a **malicious release of an otherwise-legitimate dependency or
CI action** (maintainer-account takeover, a poisoned transitive, or a retroactively
repointed Git tag — cf. the `tj-actions/changed-files` tag poisoning, March 2025).
The controls below are defense-in-depth; none alone is sufficient.

| Threat | Mitigation |
|---|---|
| A dependency or plugin is swapped for a malicious build (hijacked artifact, MITM of a repository) | Repositories are restricted to `mavenCentral()` + `gradlePluginPortal()` over HTTPS — no HTTP or untrusted mirrors — and Maven Central artifacts are immutable, so a published coordinate cannot be silently re-bytes'd. All versions are pinned in a single version catalog with no dynamic (`+` / `latest.release`) ranges. **Gradle dependency-verification checksums are intentionally *not* used:** with Dependabot auto-merging patch/minor bumps, the metadata would have to be regenerated automatically from whatever was just downloaded and approved unattended, which notarizes the artifact rather than vetting it — providing no protection against a malicious *release* (the actual threat) while breaking the build on every bump. The "is this version known-bad?" question is instead answered by `dependency-review-action` (next row). |
| The Gradle distribution itself is tampered with | `gradle-wrapper.properties` carries `distributionSha256Sum`, so the wrapper refuses to run a distribution that doesn't match the published checksum. CI additionally runs `gradle/actions/wrapper-validation` to confirm `gradle-wrapper.jar` matches a known-good Gradle release. |
| A CI action is repointed to malicious code via a mutable tag | Every GitHub Actions `uses:` is pinned to a full **commit SHA** (with the human-readable version in a trailing comment), not a floating `@vN` tag. This is most important for third-party actions that run in privileged jobs (e.g. `softprops/action-gh-release` in the release pipeline). |
| A compromised dependency release is merged automatically | The Dependabot auto-merge workflow only auto-approves **patch and minor** bumps, and **never** auto-merges GitHub Actions updates (a privileged surface) — majors and action bumps require human review. A green CI run is not treated as evidence that a newly published version is trustworthy. |
| A known-vulnerable dependency is introduced | `actions/dependency-review-action` fails any PR that adds a dependency with a high-severity advisory before it can merge. Dependabot tracks the `gradle`, `npm`, and `github-actions` ecosystems (the npm SDK and each demo's Playwright e2e suite included) so fixes are surfaced promptly. |
| A forged or unsigned release reaches consumers | Maven Central artifacts are GPG-signed in CI (`release.yml`); the signing key, passphrase, and Central Portal credentials are injected from GitHub secrets at publish time, scoped to the publish steps only and never exposed to the third-party release action. Releases are triggered exclusively by maintainer-pushed `vX.Y.Z` tags or manual dispatch, so untrusted PR code cannot trigger a publish. CI itself runs on `pull_request` with `contents: read`, so fork PRs execute without secret access. |
| Secrets leak through the repository | No secrets are committed (`.gitignore` covers `.env`); release credentials exist only as GitHub secrets and, on the ephemeral runner, in a `chmod 600` `~/.gradle/gradle.properties` written at publish time. |

**Residual risk.** Without artifact-checksum pinning, the project trusts Maven
Central's and the Gradle Plugin Portal's own integrity (immutability + TLS) for the
bytes behind each pinned coordinate; a compromise of those registries themselves is
out of scope. Auto-merged patch/minor dependency bumps are gated by CI and
`dependency-review-action` but are not human-reviewed, so a malicious release that is
not yet in the advisory database could land — keep the auto-merge window to patch/minor
and rely on the advisory feed and post-merge Dependabot alerts. The npm SDK is published
manually (see `RELEASE.md`) and is not yet covered by a provenance attestation
(`npm publish --provenance`). Neither the Maven nor npm release is reproducible-build
verified. These are accepted for now; revisit if the project adopts SLSA provenance.

## AI-authored code (provenance)

Substantially all of pk-auth's code was written by an AI coding agent, with a human
acting as product manager and architect (see the README's *DISCLAIMER from the human*
and *Comments from the human*). That makes the **authoring step itself** a supply-chain
surface, distinct from the dependency/build chain above — and a less well-understood
one, since the security posture of AI coding agents is still nascent.

Conventional software trust rests on accountable human authorship: identifiable people
whose access is vetted and whose mistakes are bounded by skill and reviewable intent.
An AI author breaks those assumptions. It is **unaccountable** (no identity, stake, or
persistence), **manipulable** through the content it reads, **high-volume** (it emits
confident, idiomatic-looking code faster than anyone can deeply review — which erodes
the very review it depends on), and is **itself an opaque supply chain** (model weights,
inference provider, agent harness, system prompt, and any connected tools). The right
mental model is to treat AI-generated code like a contribution from an *unvetted external
contributor with very high output and no accountability* — trustworthy only after
independent human review, never by provenance. The dominant realistic risk is **not** a
deliberately planted backdoor (low probability) but confident-but-subtly-wrong code,
manipulation via injected instructions, and the human review process decaying under volume.

The table below describes the situation **as it actually stands today** — these are
current realities and partial mitigations, not guarantees the project enforces.

| Threat | Current reality / partial mitigation |
|---|---|
| Confident-but-subtly-wrong security code (auth bypass, weak defaults, timing leaks) that passes review *because* it looks idiomatic | The code has **not** had an independent security review; the README states this plainly. The human author reviews and merges every PR but is not acting as a dedicated security reviewer, and intends to seek a third-party review. The test suites, CI gate, and `dependency-review-action` catch some classes; defense-in-depth means no single AI-written check is the only control. The earlier in-repo security review was *itself* AI-produced and carries the same caveat. |
| Hallucinated or typosquatted (“slopsquat”) dependency introduced by the agent | Dependencies are pinned in a single version catalog with no dynamic ranges; `dependency-review-action` runs on PRs; the human reviews each diff. No automated check specifically verifies that a newly added coordinate is the genuine, intended package. |
| Indirect prompt injection — malicious instructions hidden in content the agent ingests (issue text, dependency changelogs/release notes, fetched web pages, repo files, tool / MCP output) steering it to insert a backdoor, weaken a check, or exfiltrate | The agent does read such content during development (e.g. dependency release notes, fetched checksums/SHAs, repo files). The mitigation in place is human review of the resulting diffs and the harness's per-action permission prompts. There is no automated detection of injected instructions; reviewing the *entire* diff (not just the described change) is the practical defense. |
| Excessive agency — the agent can edit code and CI, push branches, open PRs, and invoke the network | Today the **human** triggers tagged releases, holds the GPG signing keys and Central Portal / npm credentials, and merges PRs; the agent holds none of those and operates under the harness's permission model. Releases are signed and maintainer-gated (see [Supply chain](#supply-chain)). |
| Model / harness / provider compromise (poisoned weights, a malicious harness or MCP update) — a “trusting trust” problem one layer up | Trusted by necessity and out of scope to fully mitigate. Reliance is reduced only indirectly: independent test oracles, pinned build tooling, and human review of output. |
| Review fatigue / automation bias — AI output outpacing genuine scrutiny | A real, unquantified limitation for a project of this size built this way. Acknowledged here rather than mitigated; the honest control is keeping unreviewed volume within what a human can actually understand and own. |

**Residual risk.** This is the bluntest item in the model: pk-auth's code is AI-authored
and, absent the third-party security review noted in the README, should be treated as
**not production-trustworthy on provenance grounds** — evaluate it on its merits, with
your own review, before relying on it. Note the self-referential limit: this section was
itself written by the AI agent, so it cannot be relied upon *because* the agent produced
it — a manipulated or mistaken agent would not faithfully document its own risks. A human
must validate this analysis like any other AI-authored artifact in the repo.

## Token revocation

Two complementary primitives ship with pk-auth as of 1.1.0:

1. **`AccessTokenStore` (ADR 0015)** — positive allow-list. Every issued JWT's JTI is
   persisted server-side; the validator looks it up on every request. Deleting the row
   (logout, admin revoke, password reset, user delete) immediately invalidates the
   bearer, well before its `exp`. This is the paved-road for revocability.
2. **`RevocationCheck` (1.0)** — negative deny-list. Lightweight in-process hook for hosts
   that issue many millions of tokens per day and want to invalidate a small subset
   proactively (e.g. a "session revoked" stream from a security event bus). Still
   supported; orthogonal to `AccessTokenStore`.

The default `AccessTokenStore.noop()` keeps the legacy stateless-JWT behaviour for hosts
that prefer it — the call costs an always-true return. Choose the binding based on traffic
shape, not as a feature toggle.

For session-lifetime management (re-using a single login across days/weeks without
re-authenticating), the rotating refresh-token primitive is the paved road — see
"Refresh-token replay defense" below.

## Refresh-token replay defense

Rotating refresh tokens with family-based replay detection are shipped via
`pk-auth-refresh-tokens` (ADR 0013). The properties the design guarantees:

- **Atomic mark-and-insert.** The SPI's `rotateAtomically` primitive marks the parent
  used AND inserts the successor as a single atomic operation (JDBI transaction,
  DynamoDB `TransactWriteItems`, or in-memory `compute` block). A non-atomic sequence
  has a window where a concurrent rotator's family-scorch can miss the freshly-inserted
  successor; the SPI contract forbids this and the concurrent-race test enforces it.
- **Hash-before-mark-used.** The service hashes the presented secret and compares
  against the stored row hash *before* invoking `rotateAtomically`. A presented
  refresh-id with the wrong secret returns `Unknown`, never burns the legitimate
  token's `used_at`. This is enforced by the
  `wrongSecretReturnsUnknownAndDoesNotBurnLegitToken` parity test on every backend.
- **Replay → family scorch.** Re-presenting a used or revoked refresh from a known
  family triggers a `revokeFamily(familyId, ROTATION_REPLAY)` call that runs outside
  the failed rotation. The result is that BOTH the attacker AND the legitimate client
  lose the session — the legit user sees their next refresh fail and is redirected to
  login. The cost is one ceremony; the alternative is a leaked session that survives
  the legit client's rotation.
- **Concurrent rotation: exactly one wins.** The non-negotiable race test launches 8
  threads rotating the same token simultaneously. Exactly one thread returns
  `RotateResult.Success`; the other 7 return `RotateResult.Replayed`; the entire
  family (root + the winner's successor) is revoked. This test passes against
  Postgres (JDBI transaction path) and DynamoDB Local (`TransactWriteItems` path) on
  every CI run.
- **Hash-at-rest.** The 32-byte secret is SHA-256-hashed before storage; the raw
  secret is never persisted. The wire token (`{refreshId}.{secret}`, base64url on
  both halves) must NEVER be logged.

## Data at rest

pk-auth stores the following PII in its persistence layers:

| Field | Persistence | Default protection |
|---|---|---|
| `email` | JDBI (Postgres) or DynamoDB | Plaintext |
| `phone_e164` | JDBI (Postgres) or DynamoDB | Plaintext |
| Backup code hashes | JDBI or DynamoDB | Argon2id |
| Public keys / credential IDs | JDBI or DynamoDB | Plaintext (public data) |

### DynamoDB

DynamoDB enables SSE-S3 at rest by default. For higher assurance, enable
**SSE-KMS with a customer-managed CMK** so that key rotation and access auditing are
under the operator's control. Configure this in the table settings; pk-auth does not
create the table at runtime.

### Postgres (JDBI)

Postgres does **not** enable column-level or filesystem encryption by default. The
`phone_e164` and `email` columns are stored as plaintext. Operators should consider:

- **(a) Filesystem / volume encryption** — encrypt the underlying block device or
  filesystem (e.g. LUKS, AWS EBS encryption). Protects against physical media theft
  but not SQL-level data exfiltration.
- **(b) Column-level encryption with `pgcrypto`** — wrap `phone_e164` / `email` at
  write time using `pgp_sym_encrypt` / `pgp_sym_decrypt`. The encryption key must be
  injected from outside the database. pk-auth's Flyway schema does not do this today;
  hosts with strict data-classification requirements should layer it in a custom
  migration on top of the shipped baseline.
- **(c) HMAC-keyed index columns** — if exact-match lookups on `email` or `phone_e164`
  are required but storing plaintext is unacceptable, store an HMAC (SHA-256 with a
  server-side key) in a separate indexed column and perform queries against that column.
  The plaintext is then replaced with the encrypted ciphertext in the main column.

## Operator self-test

A deployment that survives the following spot checks is in reasonable shape:

1. Start the demo with the wrong `pkauth.relying-party.id`. Confirm Chrome rejects with
   "relying party not registrable."
2. Register a passkey, capture the assertion's signing counter, then replay an old assertion
   with a lower counter. Confirm the server rejects with `counter_regression`.
3. Delete the only credential on a user via the admin API. Confirm a 409.
4. Send the JWT in `Authorization: Bearer <token>` to a host-app endpoint that does not
   call `PkAuthJwtValidator`. Confirm the host's own filter chain rejects it (proves pk-auth
   isn't the only thing standing between the bearer and your code).
5. Restart the app and confirm Flyway / DynamoDB schema reconciles without manual intervention.

---

## Document drift

Documentation in this file trails code changes. For ground truth, `grep` the source:

```sh
# Find all SPI interfaces
grep -r "interface.*Repository\|interface.*Store\|interface.*Sender\|interface.*Check\|interface.*Lookup" pk-auth-core/src pk-auth-jwt/src

# Find challenge handling
grep -r "takeOnce\|ChallengeStore" pk-auth-core/src
```

If this document contradicts the code, the code wins.
