// SPDX-License-Identifier: MIT

/**
 * pk-auth core module: framework-neutral SPIs, DTOs, sealed result types, configuration, and the
 * {@code PasskeyAuthenticationService} contract. The {@code internal} package is intentionally not
 * exported.
 */
module com.codeheadsystems.pkauth.core {
  requires transitive org.jspecify;
  requires transitive com.fasterxml.jackson.annotation;
  requires transitive tools.jackson.databind;
  requires transitive com.webauthn4j.core;
  requires com.github.benmanes.caffeine;
  requires org.slf4j;

  // Optional Micrometer integration: present at compile time, may be absent at runtime.
  requires static micrometer.core;

  exports com.codeheadsystems.pkauth.api;
  exports com.codeheadsystems.pkauth.ceremony;
  exports com.codeheadsystems.pkauth.config;
  exports com.codeheadsystems.pkauth.credential;
  exports com.codeheadsystems.pkauth.error;
  exports com.codeheadsystems.pkauth.json;
  exports com.codeheadsystems.pkauth.metrics;
  exports com.codeheadsystems.pkauth.spi;
}
