// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import javax.sql.DataSource;
import org.flywaydb.core.Flyway;

/**
 * Convenience helper to run pk-auth's Flyway migrations against a {@link DataSource}.
 *
 * <p>For development and test use only. The {@link #migrateForDevelopment(DataSource)} helper is
 * scoped to demos and integration tests. Production hosts must drive Flyway themselves so they can
 * control the target schema version, baseline settings, out-of-order handling, and other
 * operational parameters, by adding {@code classpath:db/migration} from this artifact to the host's
 * existing Flyway location list.
 *
 * <p>The current schema version shipped by this library is {@value #CURRENT_SCHEMA_VERSION}.
 */
public final class PkAuthJdbiSchema {

  /**
   * The highest Flyway migration version shipped by this library. {@link
   * #migrateForDevelopment(DataSource)} pins Flyway's {@code target} to this value so that
   * unreleased migrations on the classpath are never applied accidentally.
   */
  public static final String CURRENT_SCHEMA_VERSION = "12";

  private PkAuthJdbiSchema() {}

  /**
   * Runs pk-auth's Flyway migrations up to {@link #CURRENT_SCHEMA_VERSION} on the supplied {@code
   * dataSource}. Idempotent.
   *
   * <p>For development and integration testing only. Production code must not call this method;
   * production hosts should configure Flyway independently.
   */
  public static void migrateForDevelopment(DataSource dataSource) {
    Flyway.configure()
        .dataSource(dataSource)
        .locations("classpath:db/migration")
        .target(CURRENT_SCHEMA_VERSION)
        .load()
        .migrate();
  }
}
