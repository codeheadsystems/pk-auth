# 19. Crypto-agility and post-quantum readiness for passkey algorithms

Date: 2026-06-17

## Status

Accepted.

## Context

A passkey is a public-key credential. Its signature algorithm, whether ES256 (ECDSA P-256), EdDSA
(Ed25519), or RS256/RS384 (RSA), rests on discrete-log or factoring hardness that a
cryptographically relevant quantum computer (CRQC) running Shor's algorithm would break. No such
computer exists today, but stored public keys are long-lived, so the project states its posture
accurately and removes the obstacles to a future migration.

Two concrete problems existed in the code:

1. Two divergent, hardcoded COSE algorithm lists. The registration create-options sent to the
   browser hardcoded `-7` (ES256), `-8` (EdDSA), and `-257` (RS256) in
   `DefaultPasskeyAuthenticationService`. The registration verify path hardcoded a different list,
   `DEFAULT_PUB_KEY_PARAMS` (ES256, EdDSA, RS256, ES384, RS384), in `WebAuthn4JConverters`. The two
   could drift, and neither was operator-configurable.
2. No way to see which stored credentials use which algorithm, so a future "re-enrol off algorithm
   X" campaign had nothing to drive it.

The scope is limited. No post-quantum signature algorithm can be added to pk-auth today. The choice
is gated end to end by the authenticator hardware, CTAP2/FIDO2, the WebAuthn/COSE registry, and
WebAuthn4J's verifier, none of which yet standardises or implements a PQC signature (for example an
ML-DSA / FIPS 204 COSE binding). Inventing COSE identifiers or faking ML-DSA/Dilithium support would
be non-interoperable. The realistic goal is therefore crypto-agility and accurate documentation, not
new algorithms.

A related but separate question is the post-ceremony JWT. The earlier "HS256 for dev, ES256 for
production" framing was misleading. HMAC-SHA256 is not broken by Shor, and with the enforced
≥ 256-bit key it retains about 128-bit security under Grover, which makes HS256 the
quantum-conservative choice for a single-issuer, single-verifier deployment. ES256 JWTs exist for
untrusted third-party verification and are Shor-vulnerable, with exposure bounded by the short token
TTL.

## Decision

1. A single source of truth for COSE algorithms. Introduce a framework-neutral `CoseAlgorithm` enum
   and carry two ordered lists on `CeremonyConfig`: `offeredAlgorithms` (advertised in
   create-options) and `acceptedAlgorithms` (enforced on verify). Both the create-options ceremony
   and the WebAuthn4J verify path derive their lists from this config, and the two hardcoded lists
   are removed. `acceptedAlgorithms` is authoritative, and `offeredAlgorithms` must be a subset and
   may be narrower. Operators can narrow either without code changes.

2. Backward-compatible defaults. The default `acceptedAlgorithms` is the union of everything
   previously accepted (ES256, EdDSA, RS256, ES384, RS384), so no already-registered credential can
   fail verification. The default `offeredAlgorithms` stays the historical create-options subset
   (ES256, EdDSA, RS256). A new 5-arg `CeremonyConfig` convenience constructor applies these
   defaults, so every existing call site compiles and behaves identically.

3. Per-credential algorithm visibility. `CredentialAlgorithms.coseAlgorithm(record)` decodes the
   COSE algorithm already embedded in the stored public key, with no schema change, and
   `AdminService.listCredentialsByAlgorithm(actor, target, coseAlgorithm)` reports which credentials
   use a given algorithm. This is the read side a re-enrolment campaign drives off.

4. Accurate JWT framing. HS256 versus ES256 is documented as a trust-topology choice (symmetric,
   shared trust boundary versus asymmetric, untrusted third-party verification) with the
   post-quantum trade-off spelled out. No signing behaviour or default changes.

5. Documentation. Add a "Post-quantum readiness" section to the threat model and a TLS hybrid-KEM
   ("harvest-now, decrypt-later") note to the operator guide. The note is framed as an operator
   action at the TLS terminator, not a library change.

## Consequences

- Positive, the divergence bug is gone: offered and accepted algorithms come from one config, so
  they can no longer silently drift, and both are operator-tunable.
- Positive, a PQC signature becomes a small, localised change: when the ecosystem standardises one,
  adding it is a new `CoseAlgorithm` constant plus its WebAuthn4J mapping, because the ceremony and
  verify code are already config-driven.
- Positive, migration is observable: operators can enumerate credentials by algorithm before a CRQC
  exists and stage re-enrolment.
- Neutral, no new algorithms: this ADR ships zero new signature algorithms. It provides readiness,
  not a PQC implementation.
- Negative, `CeremonyConfig` grew two fields: the defaulting convenience constructor and the
  `from(...)` overload leave existing construction sites and adapters unaffected.
- Constraint, the symmetric side needs no change: random secrets (refresh 32 B, OTP pepper ≥ 16 B
  with 32 B recommended, challenge 32 B) and HS256 (≥ 32 B key) are 256-bit-class and
  Grover-resistant, so nothing changed there.

## Open follow-ups

- ~~Wire `offeredAlgorithms` / `acceptedAlgorithms` through each adapter's external host config.~~
  Done: bound under `pkauth.ceremony.offered-algorithms` / `pkauth.ceremony.accepted-algorithms` in
  the Spring starter (`PkAuthProperties.Ceremony`) and Micronaut adapter (`PkAuthConfiguration`),
  and as the `PkAuthConfig.Ceremony(offeredAlgorithms, acceptedAlgorithms)` record components in the
  Dropwizard adapter. Each adapter null-coalesces to the core defaults and passes the lists to the
  seven-argument `CeremonyConfig.from(...)`. All three example apps set them explicitly (to the
  defaults) as living documentation.
- Revisit when a COSE-registered post-quantum signature algorithm lands in WebAuthn4J. Adding it is
  the localised change this ADR enables.
