// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.codeheadsystems.pkauth.spring.autoconfigure.PkAuthJdbiPersistenceAutoConfiguration;
import org.h2.jdbcx.JdbcDataSource;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * Verifies the JDBI persistence autoconfig activates iff a {@link Jdbi} bean is present, and
 * registers every SPI bean once activated. The test does not run real queries; Jdbi is wired
 * against an H2 datasource that is never touched, since the test only inspects the application
 * context.
 */
class PkAuthJdbiPersistenceAutoConfigurationTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(PkAuthJdbiPersistenceAutoConfiguration.class));

  @Test
  void inactiveWithoutJdbiBean() {
    runner.run(
        ctx ->
            assertThat(ctx)
                .doesNotHaveBean("pkAuthJdbiCredentialRepository")
                .doesNotHaveBean("pkAuthJdbiUserLookup"));
  }

  @Test
  void activatesWhenJdbiBeanIsPresent() {
    runner
        .withBean("jdbi", Jdbi.class, () -> Jdbi.create(h2DataSource()))
        .run(
            ctx ->
                assertThat(ctx)
                    .hasSingleBean(CredentialRepository.class)
                    .hasSingleBean(UserLookup.class)
                    .hasSingleBean(ChallengeStore.class)
                    .hasSingleBean(BackupCodeRepository.class)
                    .hasSingleBean(OtpRepository.class));
  }

  private static JdbcDataSource h2DataSource() {
    JdbcDataSource ds = new JdbcDataSource();
    ds.setUrl("jdbc:h2:mem:pkauth-coverage-test;DB_CLOSE_DELAY=-1");
    return ds;
  }
}
