// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.codeheadsystems.pkauth.jwt.CeremonyOrchestrator;
import com.codeheadsystems.pkauth.spring.web.PkAuthCeremonyController;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Verifies how the ceremony controller is registered when only the starter's autoconfiguration is
 * in play. Unlike {@link PkAuthTestApplication}, the host configurations here do not component-scan
 * the starter's packages, so the controller comes solely from {@code PkAuthWebAutoConfiguration}.
 */
class PkAuthCeremonyControllerRegistrationTest {

  private static final String START_REGISTRATION_BODY =
      "{\"username\":\"registration-test\",\"displayName\":\"Registration Test\"}";

  // The host configurations are nested inside the @Nested test classes so Spring Boot's
  // TestTypeExcludeFilter keeps them out of PkAuthTestApplication's component scan.

  @Nested
  @SpringBootTest(classes = WithoutHostController.DefaultHost.class)
  class WithoutHostController {

    @Autowired private WebApplicationContext context;

    @Test
    void defaultControllerIsRegisteredAndMapped() throws Exception {
      Map<String, PkAuthCeremonyController> controllers =
          context.getBeansOfType(PkAuthCeremonyController.class);
      assertThat(controllers).containsOnlyKeys("pkAuthCeremonyController");
      assertThat(controllers.get("pkAuthCeremonyController"))
          .isExactlyInstanceOf(PkAuthCeremonyController.class);

      assertStartRegistrationIsServed(context);
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class DefaultHost {}
  }

  @Nested
  @SpringBootTest(classes = WithHostController.OverridingHost.class)
  class WithHostController {

    @Autowired private WebApplicationContext context;

    @Test
    void hostControllerReplacesDefaultAndIsMapped() throws Exception {
      Map<String, PkAuthCeremonyController> controllers =
          context.getBeansOfType(PkAuthCeremonyController.class);
      assertThat(controllers).containsOnlyKeys("hostCeremonyController");
      assertThat(controllers.get("hostCeremonyController"))
          .isInstanceOf(HostCeremonyController.class);

      assertStartRegistrationIsServed(context);
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class OverridingHost {
      @Bean
      PkAuthCeremonyController hostCeremonyController(CeremonyOrchestrator orchestrator) {
        return new HostCeremonyController(orchestrator);
      }
    }

    static final class HostCeremonyController extends PkAuthCeremonyController {
      HostCeremonyController(CeremonyOrchestrator orchestrator) {
        super(orchestrator);
      }
    }
  }

  private static void assertStartRegistrationIsServed(WebApplicationContext context)
      throws Exception {
    MockMvc mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
    mockMvc
        .perform(
            post("/auth/passkeys/registration/start")
                .contentType(MediaType.APPLICATION_JSON)
                .content(START_REGISTRATION_BODY))
        .andExpect(status().isOk());
  }
}
