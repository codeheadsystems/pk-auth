// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.examples.spring;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Runnable entry point for the pk-auth Spring Boot demo. The auto-configuration in
 * pk-auth-spring-boot-starter wires every ceremony and admin endpoint; relying-party identity is
 * configured via {@code pkauth.relying-party.*} in {@code application.yml}; no custom
 * {@code @Bean @Primary RelyingPartyConfig} override is needed. To run:
 *
 * <pre>
 *   ./gradlew :examples:spring-boot-demo:bootRun
 * </pre>
 *
 * <p>The demo ships with the testkit's in-memory SPIs ({@code pkauth.dev-mode=true}), so reviewers
 * can boot the demo with no external services.
 */
@SpringBootApplication
public class SpringBootDemoApplication {

  public static void main(String[] args) {
    SpringApplication.run(SpringBootDemoApplication.class, args);
  }
}
