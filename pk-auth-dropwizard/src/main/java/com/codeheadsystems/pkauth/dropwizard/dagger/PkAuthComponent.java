// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.dagger;

import dagger.Component;
import jakarta.inject.Singleton;

/**
 * Dagger 2 component that materialises everything the bundle hands to Jersey. Brief §6.11:
 * "@Component(modules = {...}) PkAuthComponent with provision methods for the Jersey resources".
 *
 * <p>The component exposes only the ceremony pieces declared on {@link PkAuthCeremonyGraph}
 * (resource + JWT issuer/validator + authenticator + deletion service + optional refresh handler).
 * The admin graph lives in {@link PkAuthFullComponent} so applications without {@code
 * pk-auth-admin-api} on the classpath do not pay for it.
 */
@Singleton
@Component(modules = {PkAuthModule.class})
public interface PkAuthComponent extends PkAuthCeremonyGraph {}
