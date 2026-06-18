# 19. Crypto-agility and post-quantum readiness for passkey algorithms

Date: 2026-06-17

## Status

Accepted.

## Context

A passkey is a public-key credential. Its signature algorithm — ES256 (ECDSA P-256), EdDSA
(Ed25519), RS256/RS384 (RSA) — rests on discrete-log / factoring hardness that a
cryptographically-relevant quantum computer (CRQC) running Shor's algorithm would break. None
exists today, but stored public keys are long-lived, so the project should be honest about the
posture and remove the obstacles to a future migration.

Two concrete problems existed in the code:

1. **Two divergent, hardcoded COSE algorithm lists.** The registration *create-options* sent to the
   browser hardcoded `-7` (ES256), `-8` (EdDSA), `-257` (RS256) in
   `DefaultPasskeyAuthenticationService`. The registration *verify* path hardcoded a different list —
   `DEFAULT_PUB_KEY_PARAMS` (ES256, EdDSA, RS256, ES384, RS384) in `WebAuthn4JConverters`. The two
   could drift, and neither was operator-configurable.
2. **No way to see which stored credentials use which algorithm**, so a future "re-enroll off
   algorithm X" campaign had nothing to drive it.

It is important to be precise about scope. **No post-quantum signature algorithm can be added to
pk-auth today.** The choice is gated end-to-end by the authenticator hardware, CTAP2/FIDO2, the
WebAuthn/COSE registry, and WebAuthn4J's verifier — none of which yet standardize or implement a
PQC signature (e.g. an ML-DSA / FIPS 204 COSE binding). Inventing COSE identifiers or faking
ML-DSA/Dilithium support would be dishonest and non-interoperable. The realistic goal is therefore
**crypto-agility and accurate documentation**, not new algorithms.

A related but separate question is the post-ceremony JWT. The earlier "HS256 for dev, ES256 for
production" framing was misleading: HMAC-SHA256 is *not* broken by Shor, and with the enforced
≥ 256-bit key it retains ~128-bit security under Grover — making HS256 the quantum-conservative
choice for a single-issuer/single-verifier deployment. ES256 JWTs exist for untrusted third-party
verification and *are* Shor-vulnerable, with exposure bounded by the short token TTL.

## Decision

1. **One source of truth for COSE algorithms.** Introduce a framework-neutral `CoseAlgorithm` enum
   and carry two ordered lists on `CeremonyConfig`: `offeredAlgorithms` (advertised in
   create-options) and `acceptedAlgorithms` (enforced on verify). Both the create-options ceremony
   and the WebAuthn4J verify path derive their lists from this config; the two hardcoded lists are
   removed. `acceptedAlgorithms` is authoritative; `offeredAlgorithms` must be a subset and may be
   narrower. Operators can narrow either without code changes.

2. **Backward-compatible defaults.** The default `acceptedAlgorithms` is the **union** of everything
   previously accepted (ES256, EdDSA, RS256, ES384, RS384), so no already-registered credential can
   fail verification. The default `offeredAlgorithms` stays the historical create-options subset
   (ES256, EdDSA, RS256). A new 5-arg `CeremonyConfig` convenience constructor applies these defaults
   so every existing call site compiles and behaves identically.

3. **Per-credential algorithm visibility.** `CredentialAlgorithms.coseAlgorithm(record)` decodes the
   COSE algorithm already embedded in the stored public key — **no schema change** — and
   `AdminService.listCredentialsByAlgorithm(actor, target, coseAlgorithm)` reports which credentials
   use a given algorithm, the read side a re-enrollment campaign drives off.

4. **Honest JWT framing.** Re-document HS256 vs ES256 as a trust-topology choice (symmetric, shared
   trust boundary vs asymmetric, untrusted third-party verification) with the post-quantum tradeoff
   spelled out. **No signing behavior or default changes.**

5. **Documentation.** Add a *Post-quantum readiness* section to the threat model and a TLS
   hybrid-KEM ("harvest-now, decrypt-later") note to the operator guide, the latter framed explicitly
   as an operator action at the TLS terminator, not a library change.

## Consequences

- **Positive — the divergence bug is gone.** Offered and accepted algorithms come from one config;
  they can no longer silently drift, and both are operator-tunable.
- **Positive — a PQC signature becomes a small, localized change.** When the ecosystem standardizes
  one, adding it is a new `CoseAlgorithm` constant plus its WebAuthn4J mapping — the ceremony and
  verify code are already config-driven.
- **Positive — migration is observable.** Operators can enumerate credentials by algorithm before a
  CRQC exists and stage re-enrollment.
- **Neutral — no new algorithms, by design.** This ADR deliberately ships zero new signature
  algorithms; it is readiness, not a PQC implementation.
- **Negative — `CeremonyConfig` grew two fields.** Mitigated by the defaulting convenience
  constructor and the `from(...)` overload, so existing construction sites and adapters are
  unaffected.
- **Constraint — the symmetric story is already fine.** Random secrets (refresh 32 B, OTP pepper
  ≥ 16 B / 32 B recommended, challenge 32 B) and HS256 (≥ 32 B key) are 256-bit-class and
  Grover-resistant; no change was needed or made there.

## Open follow-ups

- Wire `offeredAlgorithms` / `acceptedAlgorithms` through each adapter's external (YAML) host config.
  Today they are overridable via `CeremonyConfig` / the `PasskeyAuthenticationServices` builder; full
  per-adapter property plumbing is deferred until there is a concrete reason to narrow the lists from
  configuration.
- Revisit when a COSE-registered post-quantum signature algorithm lands in WebAuthn4J; adding it is
  the localized change this ADR was written to enable.
