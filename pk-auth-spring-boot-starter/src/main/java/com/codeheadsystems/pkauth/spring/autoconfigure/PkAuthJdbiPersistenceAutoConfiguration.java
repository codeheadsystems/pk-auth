// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.autoconfigure;

import com.codeheadsystems.pkauth.persistence.jdbi.JdbiBackupCodeRepository;
import com.codeheadsystems.pkauth.persistence.jdbi.JdbiChallengeStore;
import com.codeheadsystems.pkauth.persistence.jdbi.JdbiCredentialRepository;
import com.codeheadsystems.pkauth.persistence.jdbi.JdbiOtpRepository;
import com.codeheadsystems.pkauth.persistence.jdbi.JdbiUserLookup;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;
import org.jdbi.v3.core.Jdbi;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * Wires the JDBI persistence module's SPI implementations when both:
 *
 * <ul>
 *   <li>{@code pk-auth-persistence-jdbi} is on the classpath, and
 *   <li>a {@link Jdbi} bean is provided by the host application (the starter does not own the
 *       datasource; the brief leaves connection pool and migration ownership to the host).
 * </ul>
 *
 * <p>This autoconfig is loaded before {@link PkAuthAutoConfiguration} so the JDBI beans register
 * first; the testkit in-memory defaults then back off via {@link ConditionalOnMissingBean}. If both
 * JDBI and DynamoDB modules are on the classpath the host app picks the winner by which underlying
 * client bean it supplies; see the README for the convention.
 */
@AutoConfiguration(before = PkAuthAutoConfiguration.class)
@ConditionalOnClass({Jdbi.class, JdbiCredentialRepository.class})
@ConditionalOnBean(Jdbi.class)
public class PkAuthJdbiPersistenceAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public CredentialRepository pkAuthJdbiCredentialRepository(Jdbi jdbi) {
    return new JdbiCredentialRepository(jdbi);
  }

  @Bean
  @ConditionalOnMissingBean
  public UserLookup pkAuthJdbiUserLookup(Jdbi jdbi) {
    return new JdbiUserLookup(jdbi);
  }

  @Bean
  @ConditionalOnMissingBean
  public ChallengeStore pkAuthJdbiChallengeStore(Jdbi jdbi) {
    return new JdbiChallengeStore(jdbi);
  }

  @Bean
  @ConditionalOnMissingBean
  public BackupCodeRepository pkAuthJdbiBackupCodeRepository(Jdbi jdbi) {
    return new JdbiBackupCodeRepository(jdbi);
  }

  @Bean
  @ConditionalOnMissingBean
  public OtpRepository pkAuthJdbiOtpRepository(Jdbi jdbi) {
    return new JdbiOtpRepository(jdbi);
  }
}
