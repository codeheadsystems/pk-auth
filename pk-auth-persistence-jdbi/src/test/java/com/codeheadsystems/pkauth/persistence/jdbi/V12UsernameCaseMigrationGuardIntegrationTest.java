// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Exercises the pre-flight guard in {@code V12__users_username_case_insensitive.sql} against a real
 * Postgres, on a database that is dirty in exactly the way the guard exists to catch.
 *
 * <p>This needs its own container: the shared {@link PostgresFixture} is already migrated to head,
 * and the interesting states here are "stopped at V11 with case-duplicate rows" and "stopped at V11
 * and clean". Each test migrates to V11, seeds, then runs V12 on its own database.
 */
@Testcontainers
@DisabledIfEnvironmentVariable(named = "PKAUTH_SKIP_TESTCONTAINERS", matches = "1")
class V12UsernameCaseMigrationGuardIntegrationTest {

  @Test
  void migrationRefusesAndNamesTheConflictsWhenCaseDuplicatesExist() {
    withPostgres(
        ds -> {
          migrateTo(ds, "11");
          insertUser(ds, "\\x01", "Admin");
          insertUser(ds, "\\x02", "admin");
          insertUser(ds, "\\x03", "ADMIN");
          insertUser(ds, "\\x04", "unaffected");

          assertThatThrownBy(() -> migrateTo(ds, "12"))
              .hasMessageContaining("cannot make username uniqueness case-insensitive")
              // Names the offending group so an operator can act without hunting for it.
              .hasMessageContaining("Admin")
              .hasMessageContaining("admin")
              .hasMessageContaining("ADMIN")
              // ...and tells them what resolving it involves.
              .hasMessageContaining("credentials");

          // The guard must fail BEFORE the index exists, so a re-run after cleanup can succeed.
          assertThat(indexExists(ds)).isFalse();
        });
  }

  @Test
  void migrationSucceedsOnCleanDataAndIsThenEnforcedByTheIndex() {
    withPostgres(
        ds -> {
          migrateTo(ds, "11");
          insertUser(ds, "\\x01", "Alice");
          insertUser(ds, "\\x02", "bob");

          assertThatCode(() -> migrateTo(ds, "12")).doesNotThrowAnyException();
          assertThat(indexExists(ds)).isTrue();

          // Post-migration, a case variant of an existing username is refused by the index.
          assertThatThrownBy(() -> insertUser(ds, "\\x03", "ALICE"))
              .hasMessageContaining("users_username_lower_key");
        });
  }

  @Test
  void operatorCanResolveTheConflictAndReRunSuccessfully() {
    withPostgres(
        ds -> {
          migrateTo(ds, "11");
          insertUser(ds, "\\x01", "Admin");
          insertUser(ds, "\\x02", "admin");

          assertThatThrownBy(() -> migrateTo(ds, "12")).hasMessageContaining("differ only by case");

          // Operator picks the authoritative row and removes the other — the decision the
          // migration deliberately refuses to make for them.
          execute(ds, "DELETE FROM users WHERE username = 'admin'");

          assertThatCode(() -> migrateTo(ds, "12")).doesNotThrowAnyException();
          assertThat(indexExists(ds)).isTrue();
        });
  }

  // -- helpers ---------------------------------------------------------------------------------

  private interface DataSourceConsumer {
    void accept(HikariDataSource dataSource) throws Exception;
  }

  private static void withPostgres(DataSourceConsumer body) {
    try (PostgreSQLContainer<?> container =
        new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
            .withDatabaseName("pkauth_v12")
            .withUsername("pkauth")
            .withPassword("pkauth-test")) {
      container.start();
      HikariConfig cfg = new HikariConfig();
      cfg.setJdbcUrl(container.getJdbcUrl());
      cfg.setUsername(container.getUsername());
      cfg.setPassword(container.getPassword());
      cfg.setMaximumPoolSize(2);
      try (HikariDataSource ds = new HikariDataSource(cfg)) {
        body.accept(ds);
      }
    } catch (Exception e) {
      throw new IllegalStateException("V12 guard test failed", e);
    }
  }

  private static void migrateTo(HikariDataSource ds, String target) {
    Flyway.configure()
        .dataSource(ds)
        .locations("classpath:db/migration")
        .target(target)
        .load()
        .migrate();
  }

  private static void insertUser(HikariDataSource ds, String handleHex, String username) {
    execute(
        ds,
        "INSERT INTO users (user_handle, username, display_name) VALUES ('"
            + handleHex
            + "'::bytea, '"
            + username
            + "', '"
            + username
            + "')");
  }

  private static void execute(HikariDataSource ds, String sql) {
    try (var connection = ds.getConnection();
        var statement = connection.createStatement()) {
      statement.execute(sql);
    } catch (Exception e) {
      throw new IllegalStateException(e.getMessage(), e);
    }
  }

  private static boolean indexExists(HikariDataSource ds) {
    try (var connection = ds.getConnection();
        var statement = connection.createStatement();
        var rs =
            statement.executeQuery(
                "SELECT 1 FROM pg_indexes WHERE indexname = 'users_username_lower_key'")) {
      return rs.next();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }
}
