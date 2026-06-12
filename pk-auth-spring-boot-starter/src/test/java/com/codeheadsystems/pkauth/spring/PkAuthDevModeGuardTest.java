// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.UserVerificationRequirement;
import com.codeheadsystems.pkauth.backupcodes.BackupCodeService;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.config.CeremonyConfig;
import com.codeheadsystems.pkauth.magiclink.MagicLinkService;
import com.codeheadsystems.pkauth.otp.OtpService;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.codeheadsystems.pkauth.spring.autoconfigure.PkAuthAutoConfiguration;
import com.codeheadsystems.pkauth.testkit.InMemoryChallengeStore;
import com.codeheadsystems.pkauth.testkit.InMemoryCredentialRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryUserLookup;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.UnsatisfiedDependencyException;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * Guards the production-safety invariant: the testkit's in-memory SPI defaults must NOT activate
 * unless the host opts in via {@code pkauth.dev-mode=true}. Without the flag, a host that forgets
 * to declare persistence beans should fail to start rather than silently boot against per-JVM
 * in-memory storage.
 *
 * <p>Required adapter config (RP id/name/origins, JWT issuer/audience/secret) is set explicitly on
 * every case so we reach the dev-mode guard rather than tripping the new fail-fast guards on those
 * properties.
 */
class PkAuthDevModeGuardTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(PkAuthAutoConfiguration.class))
          .withPropertyValues(
              "pkauth.relying-party.id=example.com",
              "pkauth.relying-party.name=test",
              "pkauth.relying-party.origins[0]=https://example.com",
              "pkauth.jwt.issuer=pk-auth-test",
              "pkauth.jwt.audience=pk-auth-test-clients",
              "pkauth.jwt.secret=integration-test-secret-must-be-32-bytes");

  @Test
  void contextFailsToStartWhenDevModeUnsetAndNoHostBeans() {
    runner.run(
        ctx ->
            assertThat(ctx)
                .hasFailed()
                .getFailure()
                .isInstanceOf(UnsatisfiedDependencyException.class)
                .hasMessageContaining("CredentialRepository"));
  }

  @Test
  void contextFailsToStartWhenDevModeFalseAndNoHostBeans() {
    runner
        .withPropertyValues("pkauth.dev-mode=false")
        .run(
            ctx ->
                assertThat(ctx)
                    .hasFailed()
                    .getFailure()
                    .isInstanceOf(UnsatisfiedDependencyException.class)
                    .hasMessageContaining("CredentialRepository"));
  }

  @Test
  void inMemorySpiBeansActivateWhenDevModeTrue() {
    runner
        .withPropertyValues("pkauth.dev-mode=true")
        .run(
            ctx ->
                assertThat(ctx)
                    .hasSingleBean(CredentialRepository.class)
                    .hasSingleBean(UserLookup.class)
                    .hasSingleBean(ChallengeStore.class)
                    .hasSingleBean(BackupCodeRepository.class)
                    .hasSingleBean(OtpRepository.class));
  }

  /**
   * Security default: with no ceremony overrides, the CeremonyConfig bean must default to {@code
   * userVerification=REQUIRED} (the framework-neutral core default), not the weaker PREFERRED the
   * Spring adapter previously hardcoded.
   */
  @Test
  void ceremonyConfigDefaultsToRequiredUserVerification() {
    runner
        .withPropertyValues("pkauth.dev-mode=true")
        .run(
            ctx ->
                assertThat(ctx.getBean(CeremonyConfig.class).userVerification())
                    .isEqualTo(UserVerificationRequirement.REQUIRED));
  }

  @Test
  void ceremonyConfigHonorsUserVerificationOverride() {
    runner
        .withPropertyValues("pkauth.dev-mode=true", "pkauth.ceremony.user-verification=preferred")
        .run(
            ctx ->
                assertThat(ctx.getBean(CeremonyConfig.class).userVerification())
                    .isEqualTo(UserVerificationRequirement.PREFERRED));
  }

  /**
   * Passkey-only host: the three required core SPIs are provided but no backup-code / OTP / email
   * SPI is wired and dev-mode is off. The context must start (the alt-flow services are {@link
   * org.springframework.boot.autoconfigure.condition.ConditionalOnBean} on their backing SPI)
   * rather than forcing the host to wire those SPIs or flip dev-mode (which would log plaintext
   * credentials).
   */
  @Test
  void passkeyOnlyHostBootsWithoutAltFlowSpisOrDevMode() {
    runner
        .withBean(CredentialRepository.class, InMemoryCredentialRepository::new)
        .withBean(UserLookup.class, InMemoryUserLookup::new)
        .withBean(ChallengeStore.class, InMemoryChallengeStore::new)
        .run(
            ctx ->
                assertThat(ctx)
                    .hasNotFailed()
                    .hasSingleBean(PasskeyAuthenticationService.class)
                    .doesNotHaveBean(BackupCodeService.class)
                    .doesNotHaveBean(OtpService.class)
                    .doesNotHaveBean(MagicLinkService.class));
  }
}
