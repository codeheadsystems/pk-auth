# 4. Use Dagger 2 for the Dropwizard adapter's DI

Date: 2026-05-14

## Status

Accepted.

## Context

The Dropwizard adapter (`pk-auth-dropwizard`, Phase 9) must wire pk-auth's framework-neutral
services (`PasskeyAuthenticationService`, the JWT issuer and validator, and the optional
`AdminService`) into Jersey resources and a Dropwizard `ConfiguredBundle`. Dropwizard itself does
not ship an opinionated DI container. The realistic options were:

1. Hand-rolled wiring: a `PkAuthBundle` constructor that news everything up directly.
2. Guice with dropwizard-guice: familiar to many Dropwizard users, uses runtime reflection, and
   needs `@Inject` everywhere.
3. HK2: Jersey's own DI container. It is reflection-based, surfaces in error messages in confusing
   ways, and uses magical scoping.
4. Dagger 2: compile-time, annotation-processed DI. The generated component is a plain Java class
   that can be read directly.

The brief (`docs/history/pk-auth-build-brief.md` §3) names Dagger explicitly:

> Spring Boot → Spring DI. Micronaut → Micronaut DI. Dropwizard → Dagger 2 (compile-time,
> annotation-processed). Do not use Guice or HK2 except where Jersey itself requires HK2 wiring
> under the hood.

## Decision

Use Dagger 2 (`com.google.dagger:dagger:2.59.x` with `dagger-compiler` on the
`annotationProcessor` configuration) to wire the Dropwizard adapter's object graph. The bundle's
public API does not leak Dagger types: host applications hand the bundle a `PersistenceBindings`
object and an optional `AdminService`, and the bundle internally builds a `PkAuthComponent` (or the
larger `PkAuthFullComponent` when the alt-flow modules are auto-wired) whose provision methods
Jersey resources consume.

The Dagger module structure is small:

- `PkAuthModule` provides `PasskeyAuthenticationService`, `JwtConfig`, `JwtKeyset`,
  `PkAuthJwtIssuer`, `PkAuthJwtValidator`, `PkAuthDropwizardAuthenticator`, and the
  `PkAuthCeremonyResource`. It binds to the runtime `PkAuthConfig` block via constructor injection
  on the module itself.
- `PkAuthComponent` is the `@Component` whose provision methods expose what the bundle hands to
  Jersey: `ceremonyResource()`, `passkeyAuthenticator()`, `jwtIssuer()`, `jwtValidator()`,
  `userDeletionService()`, and `refreshHandler()`.
- The optional admin path applies when `pk-auth-admin-api` is on the classpath. When the alt-flow
  modules are auto-wired, the bundle builds `PkAuthFullComponent` (`PkAuthModule` plus
  `AltFlowsModule`), which adds `adminResource()`. When a host supplies its own `AdminService`, the
  bundle instantiates `PkAuthAdminResource` directly. In both cases the admin module's compile-time
  dependency stays optional.

Generated classes live in `com.codeheadsystems.pkauth.dropwizard.dagger` and are excluded from the
JaCoCo coverage report, because auto-generated boilerplate would skew the adapter-tier 70% gate.

## Consequences

### Positive

- Validation happens at compile time. The annotation processor catches missing bindings, cycles,
  and duplicate providers, and reports them as ordinary Java compile errors. Guice throws a
  `CreationException` at injector boot, and HK2 falls back silently to no-op providers.
- Dagger uses no runtime reflection. It generates a plain `DaggerPkAuthComponent` class that
  `new`s the dependency graph in straight-line code. The code is easy to read and to step through
  in a debugger, and startup has no classpath-scanning overhead.
- The runtime footprint is small. No Guice, Spring, or HK2 jar reaches the consumer's classpath
  beyond the roughly 50 KB `dagger` runtime.
- pk-auth's own code contains no HK2 wiring. Dropwizard still wires Jersey's HK2 internally, but
  pk-auth does not register anything via HK2, so the seam is contained.
- The public API is clean. Host applications interact with `PkAuthBundle`, `PersistenceBindings`,
  and the four public records. A `Component` or `@Module` annotation never appears in their call
  sites.

### Negative

- The build gains an annotation processor. Spotless and Error Prone interact with the
  Dagger-generated sources. The build mitigates this by excluding `Dagger*` and `*_Factory*`
  patterns from both the JaCoCo report and the Spotless target.
- Bindings cannot be overridden at runtime. Tests cannot swap a binding the way Guice's
  `Modules.override` allows; they need a separate Dagger module variant. For pk-auth the effect is
  small because `PersistenceBindings` already centralises the SPI bag, so the in-memory testkit
  wiring works through the same component.
- The graph is static. Dynamic features (for example swapping the JWT keyset at runtime) need a
  layer of indirection, such as a `Supplier<JwtKeyset>` provider. The same pattern works in Guice,
  where it is more obvious.

### Neutral

- Dagger Hilt is Android-specific and Anvil targets Kotlin, so plain Dagger 2 is the fit for a JVM
  library.
- Dagger generates code that uses `dagger.internal.Provider` and similar types. If
  `pk-auth-dropwizard` ever ships a `module-info.java`, those packages need to be reachable. This
  does not block v0.x, because neither the JDBI module nor the admin-api module ships a
  `module-info.java` either.

## Alternatives considered

| Option | Reason rejected |
|---|---|
| Hand-rolled `new`s in the bundle | Works for the current graph of about 10 bindings but becomes brittle as the admin and persistence wirings expand. Dagger gives the same code shape with compile-time checking. |
| Guice | Uses runtime reflection, surfaces injection errors at boot instead of compile time, drags in a heavier runtime, and conflicts with the HK2 class loader expectations in some Jersey setups. |
| HK2 directly | Jersey's own DI container, but its error messages are opaque and Dropwizard recommends against using it as the host-application DI. |

## References

- Brief §3 (non-negotiable tech choices) and §6.11 (Dropwizard module brief).
- [Dagger 2 documentation](https://dagger.dev/dev-guide/).
- The Phase 9 implementation lives in
  `pk-auth-dropwizard/src/main/java/com/codeheadsystems/pkauth/dropwizard/dagger/`.
