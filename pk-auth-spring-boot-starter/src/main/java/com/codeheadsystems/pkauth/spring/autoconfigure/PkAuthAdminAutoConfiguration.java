// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.autoconfigure;

import com.codeheadsystems.pkauth.admin.AdminAuthorizer;
import com.codeheadsystems.pkauth.admin.AdminSafetyConfig;
import com.codeheadsystems.pkauth.admin.AdminService;
import com.codeheadsystems.pkauth.admin.DefaultAdminService;
import com.codeheadsystems.pkauth.backupcodes.BackupCodeService;
import com.codeheadsystems.pkauth.magiclink.MagicLinkService;
import com.codeheadsystems.pkauth.otp.OtpService;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.codeheadsystems.pkauth.spring.admin.PkAuthAdminController;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * Wires the admin service + controller iff {@code pk-auth-admin-api} is on the classpath (brief
 * §6.10: "If {@code pk-auth-admin-api} is on the classpath … also wires {@code
 * PkAuthAdminController}").
 *
 * <p>The {@link ConditionalOnClass} guard uses the class-name string form so this autoconfig can be
 * loaded without {@code pk-auth-admin-api} present without triggering {@code NoClassDefFoundError}
 * on the {@code @Bean} return types — Spring resolves the class names lazily.
 */
@AutoConfiguration(after = PkAuthAutoConfiguration.class)
@ConditionalOnClass(name = "com.codeheadsystems.pkauth.admin.AdminService")
public class PkAuthAdminAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public AdminAuthorizer pkAuthAdminAuthorizer() {
    return AdminAuthorizer.subjectScoped();
  }

  /**
   * Wires the admin service. The three alt-flow services are injected via {@link ObjectProvider} so
   * a passkey-only host — one that wired no backup-code / OTP / magic-link feature — still gets a
   * working admin service for credential management; the absent flows surface as {@code
   * ValidationFailed("… is not configured")} (see {@link DefaultAdminService.Dependencies}).
   */
  @Bean
  @ConditionalOnMissingBean
  public AdminService pkAuthAdminService(
      CredentialRepository credentialRepository,
      UserLookup userLookup,
      ObjectProvider<BackupCodeService> backupCodeService,
      ObjectProvider<MagicLinkService> magicLinkService,
      ObjectProvider<OtpService> otpService,
      AdminAuthorizer authorizer) {
    return DefaultAdminService.create(
        new DefaultAdminService.Dependencies(
            credentialRepository,
            userLookup,
            backupCodeService.getIfAvailable(),
            magicLinkService.getIfAvailable(),
            otpService.getIfAvailable()),
        new DefaultAdminService.Config(authorizer, AdminSafetyConfig.defaults()));
  }

  @Bean
  @ConditionalOnMissingBean
  public PkAuthAdminController pkAuthAdminController(AdminService adminService) {
    return new PkAuthAdminController(adminService);
  }
}
