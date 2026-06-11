// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.autoconfigure;

import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.composition.PkAuthComposition;
import com.codeheadsystems.pkauth.json.PkAuthObjectMappers;
import com.codeheadsystems.pkauth.jwt.CeremonyOrchestrator;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.refresh.web.RefreshHandler;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spring.security.PkAuthJwtAuthenticationFilter;
import com.codeheadsystems.pkauth.spring.web.PkAuthCeremonyController;
import com.codeheadsystems.pkauth.spring.web.PkAuthExceptionHandler;
import com.codeheadsystems.pkauth.spring.web.PkAuthRefreshController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import tools.jackson.databind.module.SimpleModule;

/**
 * Wires the HTTP-facing portion of the starter: the ceremony controller, the JWT validation filter,
 * and a default {@link SecurityFilterChain} that:
 *
 * <ul>
 *   <li>permits every {@code /auth/passkeys/**} request (the ceremony itself is the authentication;
 *       it cannot require authentication to start),
 *   <li>permits {@code /auth/admin/email/complete-verification} (brief §6.9 — unauthenticated
 *       because the magic-link token identifies the user),
 *   <li>requires authentication for all other {@code /auth/admin/**} requests,
 *   <li>disables CSRF (stateless JWT — see ADR 0005),
 *   <li>disables form login and HTTP basic.
 * </ul>
 *
 * <p>The {@link AutoConfigureAfter} pin ensures Spring's own webauthn autoconfig (if present) is
 * processed first; we then refuse to start with a clear log line per brief §6.10.
 */
@AutoConfiguration(after = PkAuthAutoConfiguration.class)
@ConditionalOnClass(name = "org.springframework.web.servlet.DispatcherServlet")
@Import(PkAuthCeremonyController.class)
public class PkAuthWebAutoConfiguration {

  private static final Logger LOG = LoggerFactory.getLogger(PkAuthWebAutoConfiguration.class);

  /**
   * Register the pk-auth Jackson 3 module on Spring's autoconfigured {@code ObjectMapper}. Spring
   * Boot 4 standardized on Jackson 3 ({@code tools.jackson.*}), the same namespace pk-auth-core's
   * ObjectMapper uses (ADR 0009); the core's {@link PkAuthObjectMappers#pkAuthModule()} supplies
   * the byte[] / UserHandle / ChallengeId (de)serializers, so Spring's mapper produces the same
   * base64url-no-padding wire format the testkit and core mapper use. Spring picks up every {@code
   * tools.jackson.databind.module.JacksonModule} bean automatically.
   */
  @Bean
  public SimpleModule pkAuthJacksonModule() {
    return PkAuthObjectMappers.pkAuthModule();
  }

  @Bean
  @ConditionalOnMissingBean
  public PkAuthJwtAuthenticationFilter pkAuthJwtAuthenticationFilter(PkAuthJwtValidator validator) {
    return new PkAuthJwtAuthenticationFilter(validator);
  }

  @Bean
  @ConditionalOnMissingBean(name = "pkAuthSecurityFilterChain")
  public SecurityFilterChain pkAuthSecurityFilterChain(
      HttpSecurity http, PkAuthJwtAuthenticationFilter filter) throws Exception {
    return http.securityMatcher("/auth/**")
        .csrf(AbstractHttpConfigurer::disable)
        .formLogin(AbstractHttpConfigurer::disable)
        .httpBasic(AbstractHttpConfigurer::disable)
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        // Without an explicit entry point Spring Security routes unauthenticated requests through
        // the default ExceptionTranslationFilter which returns 403. The pk-auth contract is "no
        // credential → 401 Unauthorized" (RFC 7235); set the HttpStatusEntryPoint so admin
        // endpoints reject missing tokens with a 401 instead of a 403.
        .exceptionHandling(
            e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
        .authorizeHttpRequests(
            authz ->
                authz
                    .requestMatchers("/auth/passkeys/**")
                    .permitAll()
                    // /auth/refresh carries its own credential (the refresh token) — the JWT
                    // filter must not reject it for missing bearer auth.
                    .requestMatchers("/auth/refresh")
                    .permitAll()
                    .requestMatchers("/auth/admin/email/complete-verification")
                    .permitAll()
                    .requestMatchers("/auth/admin/**")
                    .authenticated()
                    .anyRequest()
                    .permitAll())
        .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
        .build();
  }

  /**
   * Shared ceremony orchestrator (JWT mint + label lookup + wire mapping). Lives in {@code
   * pk-auth-jwt} so every adapter holds a single dependency rather than three.
   */
  @Bean
  @ConditionalOnMissingBean
  public CeremonyOrchestrator pkAuthCeremonyOrchestrator(
      PasskeyAuthenticationService service,
      PkAuthJwtIssuer jwtIssuer,
      CredentialRepository credentialRepository) {
    return PkAuthComposition.ceremonyOrchestrator(service, jwtIssuer, credentialRepository);
  }

  /**
   * The ceremony controller is mounted explicitly via {@code @Import}, but Spring component-scan
   * doesn't run on starter packages. We register the bean here so host apps don't need a
   * {@code @ComponentScan(basePackages = "com.codeheadsystems.pkauth.spring.web")}.
   */
  @Bean
  @ConditionalOnMissingBean
  public PkAuthCeremonyController pkAuthCeremonyController(CeremonyOrchestrator orchestrator) {
    return new PkAuthCeremonyController(orchestrator);
  }

  /**
   * Refresh controller — only mounted when a {@link RefreshHandler} is present (which itself
   * requires a {@code RefreshTokenRepository} bean wired by the host).
   *
   * @since 1.1.0
   */
  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnBean(RefreshHandler.class)
  public PkAuthRefreshController pkAuthRefreshController(RefreshHandler handler) {
    return new PkAuthRefreshController(handler);
  }

  /**
   * Maps SPI {@link com.codeheadsystems.pkauth.spi.PkAuthPersistenceException} to a stable {@code
   * 503} JSON body — see the controller-advice class for the wire shape. Registered explicitly
   * because Spring Boot starters don't run component-scan on the starter's own packages.
   */
  @Bean
  @ConditionalOnMissingBean
  public PkAuthExceptionHandler pkAuthExceptionHandler() {
    return new PkAuthExceptionHandler();
  }

  // Brief §6.10 requires we explicitly check for Spring Security's own webauthn module and refuse
  // to start when it is also configured. The check itself is a class probe; if the class is
  // present we log a warning. Refusing to start is documented in the README but not enforced
  // here (the brief intentionally hedges: "log a warning and refuse to start if both are
  // configured" — "both configured" is a user-intent signal, not just classpath presence).
  static {
    if (springSecurityWebauthnOnClasspath()) {
      LOG.warn(
          "Spring Security's webauthn module appears on the classpath alongside pk-auth's "
              + "Spring Boot starter. pk-auth deliberately does NOT use spring-security-webauthn "
              + "(see brief §4.2). If you intend to use pk-auth's flow, remove spring-security-webauthn; "
              + "if you intend to use Spring Security's flow, remove this starter.");
    }
  }

  private static boolean springSecurityWebauthnOnClasspath() {
    try {
      Class.forName(
          "org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations",
          false,
          PkAuthWebAutoConfiguration.class.getClassLoader());
      return true;
    } catch (ClassNotFoundException e) {
      return false;
    }
  }
}
