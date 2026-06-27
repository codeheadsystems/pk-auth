// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.spring.security.PkAuthJwtAuthenticationFilter;
import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;

/**
 * Unit-tests the filter-wiring guarantees of {@link PkAuthWebAutoConfiguration}: the JWT filter
 * must not be auto-registered as a global servlet filter, and the {@code /auth/**} security chain
 * must carry an early {@link Order} so a host's broad catch-all chain cannot intercept the public
 * ceremony/refresh endpoints first.
 */
class PkAuthWebAutoConfigurationUnitTest {

  private final PkAuthWebAutoConfiguration autoConfig = new PkAuthWebAutoConfiguration();

  @Test
  void jwtFilterRegistrationIsDisabledSoItDoesNotRunGlobally() {
    PkAuthJwtAuthenticationFilter filter =
        new PkAuthJwtAuthenticationFilter(mock(PkAuthJwtValidator.class));

    FilterRegistrationBean<PkAuthJwtAuthenticationFilter> registration =
        autoConfig.pkAuthJwtAuthenticationFilterRegistration(filter);

    assertThat(registration.getFilter()).isSameAs(filter);
    assertThat(registration.isEnabled()).isFalse();
  }

  @Test
  void securityFilterChainHasEarlyOrder() throws NoSuchMethodException {
    Method chainMethod =
        PkAuthWebAutoConfiguration.class.getMethod(
            "pkAuthSecurityFilterChain",
            org.springframework.security.config.annotation.web.builders.HttpSecurity.class,
            PkAuthJwtAuthenticationFilter.class);

    Order order = chainMethod.getAnnotation(Order.class);
    assertThat(order).isNotNull();
    assertThat(order.value()).isEqualTo(Ordered.HIGHEST_PRECEDENCE + 10);
  }
}
