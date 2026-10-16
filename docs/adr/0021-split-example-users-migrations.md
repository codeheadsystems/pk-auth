# 21. Separate classpath locations for core and example-users migrations

Date: 2026-10-16

## Status

Accepted.

## Context

`pk-auth-persistence-jdbi` ships its Flyway migrations as classpath resources. Up to 2.3.0 every
migration lived flat in `db/migration`, and the documented host configuration was to add
`classpath:db/migration` to the host's Flyway locations.

Two of those migrations are not pk-auth data. `V5__example_users.sql` creates a `users` table that
pk-auth does not own ([ADR 0006](./0006-userlookup-spi-not-owned.md)); it exists for the reference
`JdbiUserLookup`, the demos, and the tests. `V12__users_username_case_insensitive.sql` (2.3.0)
queries and indexes that table. A host with its own identity model has no use for either, and had
no supported way to leave them out. Hosts that extracted the scripts from the jar and excluded `V5`
failed on `V12` in 2.3.0 with `relation "users" does not exist`, and any later migration on `users`
would fail the same way.

The released migrations constrain the fix. Flyway validates each applied migration's version,
description, and checksum against the resolved script, so a released script's file name and
contents cannot change without failing validation on every database that applied it. Its location
on the classpath is not validated. Flyway also scans a location recursively, in a directory and in
a jar alike, and resolves a script reached through two overlapping locations once.

Three layouts were considered.

1. Example migrations moved to a sibling location (`db/migration-example-users`), core left in
   `db/migration`. A host with its own identity model needs no change. A host using
   `JdbiUserLookup` and the documented `classpath:db/migration` stops resolving `V5` and `V12`, and
   Flyway validation then fails on the applied-but-missing migrations until the host adds the
   second location.
2. Both sets moved into subdirectories of `db/migration` (`core`, `example-users`). The documented
   `classpath:db/migration` still resolves the full set, so every host using it is unaffected. A
   host with its own identity model lists `classpath:db/migration/core`. A host that extracted
   scripts with a non-recursive `db/migration/V*.sql` pattern finds none.
3. A guard (`to_regclass('users')`) added to `V12`. This changes a released checksum, and it leaves
   every future `users` migration to repeat the guard.

## Decision

The migrations are split into two subdirectories of `db/migration` (option 2):

- `db/migration/core` holds every table pk-auth owns. Every JDBI host applies it.
- `db/migration/example-users` holds `V5__example_users.sql`,
  `V12__users_username_case_insensitive.sql`, and every future migration on the example `users`
  table. It is opt-in.

Both sets keep one version sequence, so their numbers never collide and either set applies alone.
Every script keeps its file name and its bytes. `PkAuthJdbiSchema` publishes the three locations
as `MIGRATION_LOCATION`, `CORE_MIGRATION_LOCATION`, and `EXAMPLE_USERS_MIGRATION_LOCATION`, and adds
`CORE_SCHEMA_VERSION` beside `CURRENT_SCHEMA_VERSION`, because Flyway refuses a `target` that no
configured location resolves.

## Consequences

- The documented `classpath:db/migration` configuration resolves the same twelve migrations with the
  same checksums, so the change ships as the 2.3.1 patch release.
- A host with its own identity model applies `classpath:db/migration/core` with
  `CORE_SCHEMA_VERSION` as its target, and needs no knowledge of the example set.
- A host that copied scripts out of the jar by file pattern updates the pattern to
  `db/migration/core/V*.sql`. That integration relied on the resource layout inside the jar, which
  was never a documented surface.
- A new migration goes into exactly one of the two directories. A migration in `core` bumps both
  `CORE_SCHEMA_VERSION` and `CURRENT_SCHEMA_VERSION`; one in `example-users` bumps only
  `CURRENT_SCHEMA_VERSION`. No core migration may reference the `users` table.
- `JdbiMigrationLocationsIntegrationTest` pins the split: core alone on an empty database, core
  with the example set, the parent location, and databases migrated under the 2.3.0 flat layout.
