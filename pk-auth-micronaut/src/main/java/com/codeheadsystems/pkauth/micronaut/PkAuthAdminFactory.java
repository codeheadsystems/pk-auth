// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import com.codeheadsystems.pkauth.admin.AdminService;
import com.codeheadsystems.pkauth.admin.DefaultAdminService;
import com.codeheadsystems.pkauth.backupcodes.BackupCodeService;
import com.codeheadsystems.pkauth.magiclink.MagicLinkService;
import com.codeheadsystems.pkauth.otp.OtpService;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Requires;
import jakarta.inject.Singleton;

/**
 * Wires the optional admin surface. {@code pk-auth-admin-api} is a {@code compileOnly} dependency
 * of this adapter, the same opt-in contract the Spring Boot starter expresses with
 * {@code @ConditionalOnClass} and the Dropwizard bundle with a runtime classpath check. Keeping the
 * {@link AdminService} bean in its own {@link Factory} (rather than on {@link PkAuthFactory}) means
 * the main factory class carries no reference to {@code pk-auth-admin-api}; a host that omits the
 * module can still instantiate {@link PkAuthFactory} for the ceremony / JWT beans without tripping
 * a {@code NoClassDefFoundError} on the admin types.
 *
 * <p>The whole factory is gated with {@link Requires}{@code (classes = AdminService.class)}, so
 * Micronaut skips its {@code BeanDefinition} entirely when the admin module is absent. The {@link
 * PkAuthAdminController} is in turn gated on the resulting {@link AdminService} bean, so no {@code
 * /auth/admin/**} routes are mounted unless the host opts in.
 *
 * @since 1.1.0
 */
@Factory
@Requires(classes = AdminService.class)
public class PkAuthAdminFactory {

  @Singleton
  AdminService adminService(
      CredentialRepository credentialRepository,
      UserLookup userLookup,
      BackupCodeService backupCodeService,
      MagicLinkService magicLinkService,
      OtpService otpService) {
    return DefaultAdminService.create(
        new DefaultAdminService.Dependencies(
            credentialRepository, userLookup, backupCodeService, magicLinkService, otpService));
  }
}
