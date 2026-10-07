# 14. Per-audience JWT TTL via a TokenTtlPolicy SPI

Date: 2026-05-16

## Status

Accepted.

## Context

Through 1.0, `JwtConfig.tokenTtl` was a single `Duration`, so every JWT issued by `PkAuthJwtIssuer`
had the same lifetime. Real multi-client deployments rarely fit this shape. The motif consumer
(`/home/wolpert/projects/motif`) discovered the gap first: web sessions want 15-minute access
tokens, CLI sessions want hour-plus tokens (one re-authentication per work session, not per coffee
break), and mobile sits in between. Hosts forced to share a single TTL either give the web client a
too-long token (security loss) or give the CLI client a too-short one (UX loss).

Motif's `ConfigRefreshTokenPolicy` already maps a `session_kind` enum (`web`/`ios`/`android`/`cli`)
to per-kind TTLs and is consumed at issue time. Two designs were available:

1. Add a `Map<String, Duration> ttlByAudience` field on `JwtConfig`.
2. Introduce a `TokenTtlPolicy` SPI with `accessTtl(audience) -> Duration` and let hosts implement
   it however they want.

The map-on-config option is simpler but locks the dispatch logic into configuration. A host that
wants tier-based TTLs ("admin sessions get 5 minutes regardless of audience") or
business-hours-aware TTLs has to either override `PkAuthJwtIssuer` or push that logic up into its
own issuer.

The SPI keeps that knob open at the cost of introducing one more public type. For a library whose
whole job is composability, the SPI is the better fit. Adapters bind a default static-map
implementation via factory methods (`TokenTtlPolicy.fixed(...)`, `TokenTtlPolicy.single(...)`) so
the 90% case stays one line of configuration.

A second question is which identifier the policy is keyed on. JWT's `aud` claim is the closest
existing concept, because it already identifies "who is this token for." Motif's `session_kind` is
functionally equivalent, but pk-auth uses the standard claim rather than inventing a new label.
Hosts pick whatever audience strings make sense for their topology, and the policy does not
enumerate them. As a result, `JwtConfig.audience` (singular) is no longer a single accepted value.
It is the default audience plus the set declared by the policy's `knownAudiences()`, and the
validator accepts the union.

Versioning: this is a breaking shape change to `JwtConfig` and `PkAuthProperties.Jwt` /
`PkAuthConfig.Jwt` / `PkAuthConfiguration.Jwt`. It lands in 1.1.0. Per `docs/stability.md` and the
pattern set by ADRs 0010 and 0011, the project favours clean breaks at minor boundaries over
carrying compatibility shims. 1.0 hosts upgrading to 1.1 swap `Duration tokenTtl` for
`TokenTtlPolicy ttlPolicy` and rename `audience` accessors to `defaultAudience`. The adapter records
keep a backward-compatible auxiliary constructor, so hosts that do not use per-audience TTLs see
only a parameter rename, not a positional shift.

## Decision

Introduce a `TokenTtlPolicy` SPI in `pk-auth-jwt`:

```java
public interface TokenTtlPolicy {
  Duration accessTtl(String audience);
  default Set<String> knownAudiences() { return Set.of(); }

  static TokenTtlPolicy fixed(Duration defaultTtl, Map<String, Duration> overrides);
  static TokenTtlPolicy single(Duration ttl);
}
```

Replace `JwtConfig.tokenTtl: Duration` with `JwtConfig.ttlPolicy: TokenTtlPolicy`. Rename
`JwtConfig.audience` to `JwtConfig.defaultAudience` and add a derived `allowedAudiences()` accessor
returning `{defaultAudience} ∪ ttlPolicy.knownAudiences()`.

`JwtClaims` gains an optional `audience` field. The issuer reads it, and null means "use
`defaultAudience`." The validator returns the matched audience on
`JwtVerificationResult.Success.claims().audience()` so consumers can read what the token was
actually issued for.

Spring Boot, Dropwizard, and Micronaut config records each rename their `tokenTtl` field to
`defaultTtl` and add `ttlsByAudience: Map<String, Duration>`. Adapters build the policy via
`TokenTtlPolicy.fixed(...)` when the map is non-empty, or `TokenTtlPolicy.single(...)` otherwise.

## Consequences

- Pro: hosts can serve different client kinds from one issuer without forking `PkAuthJwtIssuer`.
- Pro: the SPI surface is two methods. Static factories cover the common "fixed map" and "single
  TTL" cases, and advanced hosts can implement their own policy (admin-session TTLs, time-of-day
  TTLs, A/B-test TTLs) without touching pk-auth.
- Pro: the validator accepts the union of audiences known to the policy, which is the natural shape
  for multi-client deployments. A single validator bean serves web, mobile, and CLI without separate
  beans per audience.
- Con: the canonical `JwtConfig` constructor changes incompatibly. Hosts upgrading from 1.0 to 1.1
  must update direct constructor calls (the `JwtConfig.defaults(...)` factory and the adapter
  properties are unchanged for the single-TTL case). `CHANGELOG.md` records the change.
- Con: `JwtClaims` records an extra (nullable) field. The legacy 5-arg constructor is preserved for
  source compatibility with code that constructs claims directly, and the canonical 6-arg
  constructor is the new shape.
- Con: hosts that implement `TokenTtlPolicy` themselves are responsible for keeping
  `knownAudiences()` consistent with what they dispatch on. Inconsistency manifests as
  `WrongAudience` rejections at validation time, which is detectable but not statically prevented.

## Open follow-ups

- A future ADR will define a `RefreshTtlPolicy` parallel for the refresh-token module (PR 3 in the
  1.1 rollout).
- If a real consumer asks for it, the matched audience can be exposed as a typed claim rather than
  only on the validator's reconstructed `JwtClaims`. Without demand, the JWT-body bloat is not
  justified.
