// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.dagger;

import com.codeheadsystems.pkauth.admin.AdminService;
import com.codeheadsystems.pkauth.backupcodes.BackupCodeService;
import com.codeheadsystems.pkauth.dropwizard.admin.PkAuthAdminResource;
import com.codeheadsystems.pkauth.magiclink.MagicLinkService;
import com.codeheadsystems.pkauth.otp.OtpService;
import dagger.Component;
import jakarta.inject.Singleton;

/**
 * Dagger component that wires the passkey ceremony graph and the alt-flow services (backup-codes,
 * magic-link, OTP) plus an {@link AdminService} and the {@link PkAuthAdminResource}.
 *
 * <p>The ceremony provision methods are inherited from {@link PkAuthCeremonyGraph}. Hosts that only
 * need the four ceremony endpoints stay on {@link PkAuthComponent}. Hosts that want the admin
 * endpoint surface auto-wired register the bundle with the alt-flow constructor; the bundle then
 * materialises this component instead.
 *
 * <p>Generated wire compatibility is verified by {@code PkAuthBundleAltFlowsIntegrationTest}.
 *
 * @since 0.9.1
 */
@Singleton
@Component(modules = {PkAuthModule.class, AltFlowsModule.class})
public interface PkAuthFullComponent extends PkAuthCeremonyGraph {

  /** Alt-flow service: backup codes. */
  BackupCodeService backupCodeService();

  /** Alt-flow service: magic-link. */
  MagicLinkService magicLinkService();

  /** Alt-flow service: OTP. */
  OtpService otpService();

  /** Admin service composed over the three alt-flow services. */
  AdminService adminService();

  /** The admin resource the bundle mounts at {@code /auth/admin}. */
  PkAuthAdminResource adminResource();
}
