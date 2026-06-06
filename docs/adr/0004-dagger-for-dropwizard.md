# 4. Use Dagger 2 for the Dropwizard adapter's DI

Date: 2026-05-14

## Status

Accepted.

## Context

The Dropwizard adapter (`pk-auth-dropwizard`, Phase 9) must wire pk-auth's framework-neutral
services — `PasskeyAuthenticationService`, the JWT issuer/validator, the optional `AdminService`,
the pk-auth services and JWT types — into Jersey resources and a Dropwizard `ConfiguredBundle`. Dropwizard
itself does not ship an opinionated DI container. The realistic options were:

1. **Hand-rolled wiring.** A `PkAuthBundle` constructor that news everything up directly.
2. **Guice + dropwizard-guice.** Familiar to many Dropwizard users, runtime reflection,
   `@Inject` everywhere.
3. **HK2.** Jersey's own DI container. Reflection-based, surfaces in error messages in confusing
   ways, magical scoping.
4. **Dagger 2.** Compile-time annotation-processed DI; the generated component is a plain Java
   class you can read.

The brief (`pk-auth-build-brief.md` §3) calls out Dagger explicitly:

> Spring Boot → Spring DI. Micronaut → Micronaut DI. **Dropwizard → Dagger 2 (compile-time,
> annotation-processed).** Do not use Guice or HK2 except where Jersey itself requires HK2 wiring
> under the hood.

This ADR records the rationale.

## Decision

Use Dagger 2 (`com.google.dagger:dagger:2.59.x` with `dagger-compiler` on the
`annotationProcessor` configuration) to wire the Dropwizard adapter's object graph. The bundle's
public API does not leak Dagger types: host applications hand the bundle a `PersistenceBindings`
object and an optional `AdminService`, and the bundle internally builds a `PkAuthComponent` (or the
larger `PkAuthFullComponent` when the alt-flow modules are auto-wired) whose provision methods
Jersey resources consume.

The Dagger module structure is intentionally small:

- `PkAuthModule` — provides `PasskeyAuthenticationService`, `JwtConfig` / `JwtKeyset` /
  `PkAuthJwtIssuer` / `PkAuthJwtValidator`, `PkAuthDropwizardAuthenticator`, and the
  `PkAuthCeremonyResource`. Bound to the runtime `PkAuthConfig` block via constructor injection
  on the module itself.
- `PkAuthComponent` — the `@Component` whose provision methods expose what the bundle hands to
  Jersey: `ceremonyResource()`, `passkeyAuthenticator()`, `jwtIssuer()`, `jwtValidator()`,
  `userDeletionService()`, and `refreshHandler()`.
- The optional admin path (when `pk-auth-admin-api` is on the classpath): when the alt-flow modules
  are auto-wired the bundle builds `PkAuthFullComponent` (`PkAuthModule` + `AltFlowsModule`), which
  adds `adminResource()`; when a host supplies its own `AdminService` the bundle instantiates
  `PkAuthAdminResource` directly. Either way the admin module's compile-time dependency stays
  optional.

Generated classes live in `com.codeheadsystems.pkauth.dropwizard.dagger` and are excluded from
the JaCoCo coverage report (they're auto-generated boilerplate that should not skew the
adapter-tier ≥70% gate).

## Consequences

### Positive

- **Compile-time validation.** Missing bindings, cycles, and duplicate providers are caught by
  the annotation processor and surface as ordinary Java compile errors. Compare with Guice
  (`CreationException` thrown at injector boot) and HK2 (silent fallback to no-op providers).
- **No runtime reflection.** Dagger generates a plain `DaggerPkAuthComponent` class that
  `new`s the dependency graph in straight-line code. Easy to read; easy to step through in a
  debugger; zero classpath scanning overhead at startup.
- **Smaller runtime footprint.** No Guice / Spring / HK2 jar on the consumer's classpath beyond
  the ~50 KB `dagger` runtime.
- **No HK2 magic in our code.** Dropwizard still wires Jersey's HK2 internally — we can't avoid
  that — but pk-auth itself does not register anything via HK2. The seam is contained.
- **Clean public API.** Host applications interact with `PkAuthBundle`, `PersistenceBindings`,
  and the four public records. They never see a `Component` or `@Module` annotation in their
  call sites.

### Negative

- **Annotation processor in the build.** Spotless / Error Prone interact with the
  Dagger-generated sources. We mitigate by excluding `Dagger*` and `*_Factory*` patterns from
  both the JaCoCo report and the spotless target.
- **No runtime override.** Tests cannot just swap a binding the way Guice's `Modules.override`
  allows; they need a separate Dagger module variant. For pk-auth this is fine because
  `PersistenceBindings` already centralizes the SPI bag, so the in-memory testkit wiring works
  through the same component.
- **Static graph.** Dynamic features (e.g. swapping the JWT keyset at runtime) need a layer of
  indirection (a `Supplier<JwtKeyset>` provider). The same pattern works in Guice but is more
  obvious there.

### Neutral

- **Dagger 2 vs Dagger Hilt vs Anvil.** Hilt is Android-specific; Anvil targets Kotlin. Plain
  Dagger 2 is the right tool for a JVM library.
- **Future Java module system.** Dagger generates code that uses `dagger.internal.Provider` etc.;
  if pk-auth-dropwizard ever ships a `module-info.java`, those packages need to be reachable.
  Not a blocker for v0.x — neither the JDBI nor the admin-api modules ship a module-info either.

## Alternatives considered

| Option | Why we said no |
|---|---|
| Hand-rolled `new`s in the bundle | Works for the current ~10-binding graph but becomes brittle as the admin / persistence wirings expand. Dagger gives us the same code-shape with compile-time checking for free. |
| Guice | Runtime reflection, surfaces injection errors at boot instead of compile, drags in a heavier runtime, conflicts with HK2's class loader expectations in some Jersey setups. |
| HK2 directly | Jersey's own DI container, but its error messages are notoriously opaque and Dropwizard explicitly recommends against using it as the host-application DI. |

## References

- Brief §3 (non-negotiable tech choices) and §6.11 (Dropwizard module brief).
- [Dagger 2 documentation](https://dagger.dev/dev-guide/).
- Phase 9 implementation lives in `pk-auth-dropwizard/src/main/java/com/codeheadsystems/pkauth/dropwizard/dagger/`.
