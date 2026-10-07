// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.dagger;

import com.codeheadsystems.pkauth.dropwizard.auth.PkAuthDropwizardAuthenticator;
import com.codeheadsystems.pkauth.dropwizard.resource.PkAuthCeremonyResource;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.lifecycle.UserDeletionService;
import com.codeheadsystems.pkauth.refresh.web.RefreshHandler;
import java.util.Optional;

/**
 * Provision methods shared by {@link PkAuthComponent} and {@link PkAuthFullComponent}: everything
 * {@link PkAuthModule} materializes for the ceremony endpoints, the auth filter, and the optional
 * refresh endpoint. The bundle registers Jersey resources against this type so both components
 * share one registration path.
 *
 * @since 2.3.0
 */
public interface PkAuthCeremonyGraph {

  /** The ceremony resource Jersey mounts at {@code /auth/passkeys}. */
  PkAuthCeremonyResource ceremonyResource();

  /** JWT validator used by the auth filter. */
  PkAuthJwtValidator jwtValidator();

  /** JWT issuer kept on the graph for resources / tests that want to mint tokens directly. */
  PkAuthJwtIssuer jwtIssuer();

  /** The authenticator the bundle plugs into Dropwizard's {@code AuthDynamicFeature}. */
  PkAuthDropwizardAuthenticator passkeyAuthenticator();

  /** User-deletion fan-out service. Always present; the listener set may be empty. */
  UserDeletionService userDeletionService();

  /**
   * Refresh handler; present only when {@code PersistenceBindings.refreshTokenRepository} is
   * non-null. The bundle uses presence to decide whether to mount {@code /auth/refresh}.
   *
   * @since 1.1.0
   */
  Optional<RefreshHandler> refreshHandler();
}
