// SPDX-License-Identifier: MIT

/**
 * pk-auth refresh-tokens module: rotating opaque tokens with family-based replay defence.
 *
 * @since 1.1.0
 */
module com.codeheadsystems.pkauth.refresh {
  requires transitive com.codeheadsystems.pkauth.core;
  requires transitive com.codeheadsystems.pkauth.jwt;
  requires org.slf4j;
  requires org.jspecify;

  exports com.codeheadsystems.pkauth.refresh;
  exports com.codeheadsystems.pkauth.refresh.spi;
  exports com.codeheadsystems.pkauth.refresh.web;
}
