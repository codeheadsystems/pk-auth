// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring;

import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.refresh.spi.RefreshTokenRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryRefreshTokenRepository;
import com.codeheadsystems.pkauth.testkit.PkAuthFixtures;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/**
 * Minimal Spring Boot application for {@link org.springframework.boot.test.context.SpringBootTest}.
 * It opts in to the starter via component-scan of the autoconfigure packages and overrides the
 * relying-party config so {@link PkAuthFixtures}'s {@code example.com} matches the testkit's {@code
 * FakeAuthenticator}.
 */
@SpringBootApplication
public class PkAuthTestApplication {

  /**
   * Overrides the property-based default so the {@code FakeAuthenticator}'s {@code example.com}
   * origin is on the allow-list. The starter's default uses {@code localhost:8080} which {@code
   * FakeAuthenticator} does not sign for.
   */
  @Bean
  @Primary
  public RelyingPartyConfig testRelyingPartyConfig() {
    return PkAuthFixtures.defaultRelyingParty();
  }

  /**
   * Wires an in-memory refresh-token repository so the {@code /auth/refresh} endpoint and the
   * matching deletion-fan-out listener activate in tests. Production hosts bind a real backend
   * (JDBI or DynamoDB).
   *
   * @since 1.1.0
   */
  @Bean
  public RefreshTokenRepository testRefreshTokenRepository() {
    return new InMemoryRefreshTokenRepository();
  }
}
