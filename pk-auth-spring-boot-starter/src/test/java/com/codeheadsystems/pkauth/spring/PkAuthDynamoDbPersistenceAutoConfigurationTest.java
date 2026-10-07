// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spring.autoconfigure.PkAuthDynamoDbPersistenceAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * The DynamoDB autoconfig is only meaningfully exercised by an integration test that wires the AWS
 * SDK against a DynamoDB Local container (deferred to the demo's tests). The test verifies the
 * negative path: without the host-supplied beans the autoconfig backs off cleanly and leaves the
 * in-memory testkit defaults from {@link
 * com.codeheadsystems.pkauth.spring.autoconfigure.PkAuthAutoConfiguration} undisturbed.
 *
 * <p>Activating the autoconfig with mock clients would crash inside the DynamoDB SDK because the
 * persistence module's constructors immediately call {@code DynamoDbEnhancedClient.table(...)} to
 * compute schema metadata; the mock has no real table backing it. The demo app exercises the
 * positive path with a real DDB Local container.
 */
class PkAuthDynamoDbPersistenceAutoConfigurationTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(
              AutoConfigurations.of(PkAuthDynamoDbPersistenceAutoConfiguration.class));

  @Test
  void inactiveWithoutClients() {
    runner.run(ctx -> assertThat(ctx).doesNotHaveBean(CredentialRepository.class));
  }
}
