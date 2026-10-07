// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.autoconfigure;

import com.codeheadsystems.pkauth.persistence.dynamodb.DynamoDbBackupCodeRepository;
import com.codeheadsystems.pkauth.persistence.dynamodb.DynamoDbChallengeStore;
import com.codeheadsystems.pkauth.persistence.dynamodb.DynamoDbCredentialRepository;
import com.codeheadsystems.pkauth.persistence.dynamodb.DynamoDbOtpRepository;
import com.codeheadsystems.pkauth.persistence.dynamodb.DynamoDbUserLookup;
import com.codeheadsystems.pkauth.persistence.dynamodb.PkAuthDynamoTables;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

/**
 * Wires the DynamoDB persistence module's SPI implementations when:
 *
 * <ul>
 *   <li>{@code pk-auth-persistence-dynamodb} is on the classpath,
 *   <li>{@link DynamoDbEnhancedClient}, {@link DynamoDbClient}, and {@link PkAuthDynamoTables} are
 *       host-supplied beans (the AWS SDK is bring-your-own; the starter never constructs the client
 *       because it owns credentials and region).
 * </ul>
 *
 * <p>Per brief §6.10, "if both jdbi and dynamodb are on the classpath, jdbi wins". This autoconfig
 * implements that as: {@link PkAuthJdbiPersistenceAutoConfiguration} runs first ({@code before =
 * PkAuthAutoConfiguration.class}); its beans register and this autoconfig skips its own via {@code
 * ConditionalOnMissingBean}.
 */
@AutoConfiguration(after = PkAuthJdbiPersistenceAutoConfiguration.class)
@ConditionalOnClass({DynamoDbEnhancedClient.class, DynamoDbCredentialRepository.class})
@ConditionalOnBean({DynamoDbEnhancedClient.class, DynamoDbClient.class, PkAuthDynamoTables.class})
public class PkAuthDynamoDbPersistenceAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public CredentialRepository pkAuthDynamoCredentialRepository(
      DynamoDbEnhancedClient enhanced, PkAuthDynamoTables tables) {
    return new DynamoDbCredentialRepository(enhanced, tables);
  }

  @Bean
  @ConditionalOnMissingBean
  public UserLookup pkAuthDynamoUserLookup(
      DynamoDbEnhancedClient enhanced, PkAuthDynamoTables tables) {
    return new DynamoDbUserLookup(enhanced, tables);
  }

  @Bean
  @ConditionalOnMissingBean
  public ChallengeStore pkAuthDynamoChallengeStore(
      DynamoDbClient client, PkAuthDynamoTables tables) {
    return new DynamoDbChallengeStore(client, tables);
  }

  @Bean
  @ConditionalOnMissingBean
  public BackupCodeRepository pkAuthDynamoBackupCodeRepository(
      DynamoDbEnhancedClient enhanced, DynamoDbClient client, PkAuthDynamoTables tables) {
    return new DynamoDbBackupCodeRepository(enhanced, client, tables);
  }

  @Bean
  @ConditionalOnMissingBean
  public OtpRepository pkAuthDynamoOtpRepository(
      DynamoDbEnhancedClient enhanced, DynamoDbClient client, PkAuthDynamoTables tables) {
    return new DynamoDbOtpRepository(enhanced, client, tables);
  }
}
