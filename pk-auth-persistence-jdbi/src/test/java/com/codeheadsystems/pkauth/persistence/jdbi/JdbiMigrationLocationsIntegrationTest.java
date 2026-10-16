// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.output.MigrateResult;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Pins the split between the core migrations and the example {@code users} migrations.
 *
 * <p>Up to 2.3.0 every migration lived flat in {@code db/migration}, so a host that excluded the
 * example {@code V5__example_users.sql} failed on {@code V12__users_username_case_insensitive.sql}
 * with {@code relation "users" does not exist}. These tests run each location set against a fresh,
 * empty database, and replay the 2.3.0 flat layout from a filesystem location to check that
 * databases migrated under it still validate against the split layout.
 */
@Testcontainers
@DisabledIfEnvironmentVariable(named = "PKAUTH_SKIP_TESTCONTAINERS", matches = "1")
class JdbiMigrationLocationsIntegrationTest {

  private static final Set<String> EXAMPLE_FILES =
      Set.of("V5__example_users.sql", "V12__users_username_case_insensitive.sql");

  private static final List<String> CORE_TABLES =
      List.of(
          "credentials",
          "challenges",
          "backup_codes",
          "otp_codes",
          "pkauth_audit_events",
          "access_tokens",
          "refresh_tokens");

  private static final AtomicInteger DATABASE_COUNTER = new AtomicInteger();

  private static PostgreSQLContainer<?> container;

  @TempDir Path tempDir;

  @BeforeAll
  static void startContainer() {
    container =
        new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
            .withDatabaseName("pkauth_locations")
            .withUsername("pkauth")
            .withPassword("pkauth-test");
    container.start();
  }

  @AfterAll
  static void stopContainer() {
    if (container != null) {
      container.stop();
    }
  }

  // -- fresh databases ---------------------------------------------------------------------------

  /** The regression test for the 2.3.0 bug: a host with its own identity model. */
  @Test
  void coreLocationAloneMigratesAnEmptyDatabaseWithoutAUsersTable() {
    try (HikariDataSource ds = freshDatabase()) {
      MigrateResult result = flyway(ds, PkAuthJdbiSchema.CORE_MIGRATION_LOCATION).migrate();

      assertThat(result.success).isTrue();
      assertThat(result.targetSchemaVersion).isEqualTo(PkAuthJdbiSchema.CORE_SCHEMA_VERSION);
      assertThat(tableExists(ds, "users")).isFalse();
      assertThat(indexExists(ds, "users_username_lower_key")).isFalse();
      CORE_TABLES.forEach(table -> assertThat(tableExists(ds, table)).as(table).isTrue());
      assertThatCode(() -> flyway(ds, PkAuthJdbiSchema.CORE_MIGRATION_LOCATION).validate())
          .doesNotThrowAnyException();
    }
  }

  /** Guards the constant against drift: it must name the highest core migration on disk. */
  @Test
  void coreSchemaVersionIsTheHighestCoreMigration() throws IOException {
    try (Stream<Path> files = Files.list(classpathDirectory("db/migration/core"))) {
      int highest =
          files
              .map(f -> f.getFileName().toString())
              .mapToInt(n -> Integer.parseInt(n.substring(1, n.indexOf("__"))))
              .max()
              .orElseThrow();
      assertThat(String.valueOf(highest)).isEqualTo(PkAuthJdbiSchema.CORE_SCHEMA_VERSION);
    }
  }

  @Test
  void coreDevelopmentHelperLeavesOutTheUsersTable() {
    try (HikariDataSource ds = freshDatabase()) {
      PkAuthJdbiSchema.migrateCoreForDevelopment(ds);

      assertThat(tableExists(ds, "users")).isFalse();
      assertThat(tableExists(ds, "credentials")).isTrue();
    }
  }

  @Test
  void coreAndExampleLocationsCreateTheUsersTableAndCaseInsensitiveIndex() {
    try (HikariDataSource ds = freshDatabase()) {
      MigrateResult result =
          flyway(
                  ds,
                  PkAuthJdbiSchema.CORE_MIGRATION_LOCATION,
                  PkAuthJdbiSchema.EXAMPLE_USERS_MIGRATION_LOCATION)
              .migrate();

      assertThat(result.success).isTrue();
      assertThat(result.targetSchemaVersion).isEqualTo(PkAuthJdbiSchema.CURRENT_SCHEMA_VERSION);
      assertThat(tableExists(ds, "users")).isTrue();
      assertThat(indexExists(ds, "users_username_lower_key")).isTrue();
      CORE_TABLES.forEach(table -> assertThat(tableExists(ds, table)).as(table).isTrue());
    }
  }

  /** The location documented before 2.3.1 still resolves all twelve migrations. */
  @Test
  void parentLocationStillResolvesTheFullSet() {
    try (HikariDataSource ds = freshDatabase()) {
      MigrateResult result = flyway(ds, PkAuthJdbiSchema.MIGRATION_LOCATION).migrate();

      assertThat(result.migrationsExecuted).isEqualTo(12);
      assertThat(tableExists(ds, "users")).isTrue();
      assertThat(indexExists(ds, "users_username_lower_key")).isTrue();
    }
  }

  /** Documented in the operator guide: overlapping locations resolve each migration once. */
  @Test
  void parentLocationTogetherWithASubdirectoryResolvesEachMigrationOnce() {
    try (HikariDataSource ds = freshDatabase()) {
      MigrateResult result =
          flyway(ds, PkAuthJdbiSchema.MIGRATION_LOCATION, PkAuthJdbiSchema.CORE_MIGRATION_LOCATION)
              .migrate();

      assertThat(result.migrationsExecuted).isEqualTo(12);
    }
  }

  // -- databases migrated under the 2.3.0 flat layout -------------------------------------------

  @Test
  void databaseWithTheExampleTableFromTheFlatLayoutValidatesAgainstTheSplitLayout()
      throws IOException {
    Path legacy = flatLegacyLayout(true);
    try (HikariDataSource ds = freshDatabase()) {
      flyway(ds, "filesystem:" + legacy).migrate();
      assertThat(indexExists(ds, "users_username_lower_key")).isTrue();

      assertThatCode(
              () ->
                  flyway(
                          ds,
                          PkAuthJdbiSchema.CORE_MIGRATION_LOCATION,
                          PkAuthJdbiSchema.EXAMPLE_USERS_MIGRATION_LOCATION)
                      .validate())
          .doesNotThrowAnyException();
      assertThatCode(() -> flyway(ds, PkAuthJdbiSchema.MIGRATION_LOCATION).validate())
          .doesNotThrowAnyException();
      assertThat(flyway(ds, PkAuthJdbiSchema.MIGRATION_LOCATION).migrate().migrationsExecuted)
          .isZero();

      // Dropping the example location on such a database is refused rather than silently
      // accepted: Flyway reports the applied example migrations as missing.
      assertThatThrownBy(() -> flyway(ds, PkAuthJdbiSchema.CORE_MIGRATION_LOCATION).validate())
          .hasMessageContaining("not resolved locally");
    }
  }

  /** The reporting host's shape: V5 excluded, so 2.3.0 stopped at V11 and failed on V12. */
  @Test
  void databaseThatExcludedTheExampleTableUpgradesWithTheCoreLocationAlone() throws IOException {
    Path legacy = flatLegacyLayout(false);
    try (HikariDataSource ds = freshDatabase()) {
      // On Postgres the failed V12 rolls back with its transaction and leaves no history row, so
      // such a database sits at V11.
      Flyway.configure()
          .dataSource(ds)
          .locations("filesystem:" + legacy)
          .target("11")
          .load()
          .migrate();
      assertThat(tableExists(ds, "users")).isFalse();

      MigrateResult result = flyway(ds, PkAuthJdbiSchema.CORE_MIGRATION_LOCATION).migrate();

      assertThat(result.success).isTrue();
      assertThat(result.migrationsExecuted).isZero();
      assertThatCode(() -> flyway(ds, PkAuthJdbiSchema.CORE_MIGRATION_LOCATION).validate())
          .doesNotThrowAnyException();
      assertThat(tableExists(ds, "users")).isFalse();
    }
  }

  // -- helpers ---------------------------------------------------------------------------------

  /** Configures Flyway as a host would: core-only hosts target the core schema version. */
  private static Flyway flyway(HikariDataSource ds, String... locations) {
    String target =
        List.of(locations).equals(List.of(PkAuthJdbiSchema.CORE_MIGRATION_LOCATION))
            ? PkAuthJdbiSchema.CORE_SCHEMA_VERSION
            : PkAuthJdbiSchema.CURRENT_SCHEMA_VERSION;
    return Flyway.configure().dataSource(ds).locations(locations).target(target).load();
  }

  /**
   * Rebuilds the 2.3.0 layout, every migration flat in one directory, from the shipped files.
   * {@code includeExample = false} reproduces a host that excluded the example migrations.
   */
  private Path flatLegacyLayout(boolean includeExample) throws IOException {
    Path flat = Files.createDirectories(tempDir.resolve("flat-2.3.0"));
    for (String location : List.of("db/migration/core", "db/migration/example-users")) {
      try (Stream<Path> files = Files.list(classpathDirectory(location))) {
        for (Path file : files.toList()) {
          String name = file.getFileName().toString();
          if (includeExample || !EXAMPLE_FILES.contains(name)) {
            Files.copy(file, flat.resolve(name));
          }
        }
      }
    }
    return flat;
  }

  private static Path classpathDirectory(String location) {
    URL url = PkAuthJdbiSchema.class.getClassLoader().getResource(location);
    assertThat(url).as(location).isNotNull();
    try {
      return Path.of(url.toURI());
    } catch (URISyntaxException e) {
      throw new IllegalStateException(e);
    }
  }

  private static HikariDataSource freshDatabase() {
    String name = "pkauth_loc_" + DATABASE_COUNTER.incrementAndGet();
    HikariConfig admin = config(container.getJdbcUrl());
    try (HikariDataSource adminDs = new HikariDataSource(admin);
        var connection = adminDs.getConnection();
        var statement = connection.createStatement()) {
      statement.execute("CREATE DATABASE " + name);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
    String url = container.getJdbcUrl().replace("/pkauth_locations", "/" + name);
    return new HikariDataSource(config(url));
  }

  private static HikariConfig config(String jdbcUrl) {
    HikariConfig cfg = new HikariConfig();
    cfg.setJdbcUrl(jdbcUrl);
    cfg.setUsername(container.getUsername());
    cfg.setPassword(container.getPassword());
    cfg.setMaximumPoolSize(2);
    return cfg;
  }

  private static boolean tableExists(HikariDataSource ds, String table) {
    return queryReturnsRow(ds, "SELECT to_regclass('public." + table + "') IS NOT NULL", true);
  }

  private static boolean indexExists(HikariDataSource ds, String index) {
    return queryReturnsRow(ds, "SELECT 1 FROM pg_indexes WHERE indexname = '" + index + "'", false);
  }

  private static boolean queryReturnsRow(HikariDataSource ds, String sql, boolean readBoolean) {
    try (var connection = ds.getConnection();
        var statement = connection.createStatement();
        var rs = statement.executeQuery(sql)) {
      if (!rs.next()) {
        return false;
      }
      return !readBoolean || rs.getBoolean(1);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }
}
