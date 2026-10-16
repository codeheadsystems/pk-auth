// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import javax.sql.DataSource;
import org.flywaydb.core.Flyway;

/**
 * Convenience helper to run pk-auth's Flyway migrations against a {@link DataSource}, and the
 * canonical names of the classpath locations those migrations ship in.
 *
 * <p>The migrations are split across two locations that share one version sequence:
 *
 * <ul>
 *   <li>{@link #CORE_MIGRATION_LOCATION} holds the tables pk-auth owns. Every JDBI host applies it.
 *   <li>{@link #EXAMPLE_USERS_MIGRATION_LOCATION} holds the example {@code users} table read by the
 *       reference {@link JdbiUserLookup}. pk-auth does not own that table; a host with its own
 *       identity model leaves this location out.
 * </ul>
 *
 * <p>{@link #MIGRATION_LOCATION} is the parent of both. Flyway scans locations recursively, so it
 * resolves the full set, exactly as it did before the split.
 *
 * <p>For development and test use only. The {@code migrate*ForDevelopment} helpers are scoped to
 * demos and integration tests. Production hosts must drive Flyway themselves so they can control
 * the target schema version, baseline settings, out-of-order handling, and other operational
 * parameters, by adding the relevant locations from this artifact to the host's existing Flyway
 * location list.
 *
 * <p>The current schema version shipped by this library is {@value #CURRENT_SCHEMA_VERSION}, and
 * the current core schema version is {@value #CORE_SCHEMA_VERSION}.
 */
public final class PkAuthJdbiSchema {

  /**
   * The highest Flyway migration version shipped by this library. {@link
   * #migrateForDevelopment(DataSource)} pins Flyway's {@code target} to this value so that
   * unreleased migrations on the classpath are never applied accidentally.
   */
  public static final String CURRENT_SCHEMA_VERSION = "12";

  /**
   * The highest Flyway migration version in {@link #CORE_MIGRATION_LOCATION}. A host that applies
   * only the core location targets this value: Flyway refuses a {@code target} that no configured
   * location resolves, and {@link #CURRENT_SCHEMA_VERSION} can belong to an example migration.
   *
   * @since 2.3.1
   */
  public static final String CORE_SCHEMA_VERSION = "11";

  /**
   * The parent location: the core and the example {@code users} migrations together.
   *
   * @since 2.3.1
   */
  public static final String MIGRATION_LOCATION = "classpath:db/migration";

  /**
   * The migrations for the tables pk-auth owns. Required by every JDBI host.
   *
   * @since 2.3.1
   */
  public static final String CORE_MIGRATION_LOCATION = "classpath:db/migration/core";

  /**
   * The migrations for the example {@code users} table read by {@link JdbiUserLookup}. Opt-in.
   *
   * @since 2.3.1
   */
  public static final String EXAMPLE_USERS_MIGRATION_LOCATION =
      "classpath:db/migration/example-users";

  private PkAuthJdbiSchema() {}

  /**
   * Runs the core and the example {@code users} migrations up to {@link #CURRENT_SCHEMA_VERSION} on
   * the supplied {@code dataSource}. Idempotent.
   *
   * <p>For development and integration testing only. Production code must not call this method;
   * production hosts should configure Flyway independently.
   */
  public static void migrateForDevelopment(DataSource dataSource) {
    migrate(
        dataSource,
        CURRENT_SCHEMA_VERSION,
        CORE_MIGRATION_LOCATION,
        EXAMPLE_USERS_MIGRATION_LOCATION);
  }

  /**
   * Runs only the core migrations up to {@link #CORE_SCHEMA_VERSION} on the supplied {@code
   * dataSource}, leaving out the example {@code users} table. Idempotent. Intended for hosts that
   * supply their own {@code UserLookup}.
   *
   * <p>For development and integration testing only. Production code must not call this method;
   * production hosts should configure Flyway independently.
   *
   * @since 2.3.1
   */
  public static void migrateCoreForDevelopment(DataSource dataSource) {
    migrate(dataSource, CORE_SCHEMA_VERSION, CORE_MIGRATION_LOCATION);
  }

  private static void migrate(DataSource dataSource, String target, String... locations) {
    Flyway.configure().dataSource(dataSource).locations(locations).target(target).load().migrate();
  }
}
