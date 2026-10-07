// SPDX-License-Identifier: MIT

/** pk-auth JWT module: issuance and validation of pk-auth-issued tokens. */
module com.codeheadsystems.pkauth.jwt {
  requires transitive com.codeheadsystems.pkauth.core;
  requires transitive com.nimbusds.jose.jwt;
  requires org.jspecify;
  requires org.slf4j;

  exports com.codeheadsystems.pkauth.composition;
  exports com.codeheadsystems.pkauth.jwt;
}
