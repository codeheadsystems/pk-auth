// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class PkAuthPersistenceResponseTest {

  @Test
  void statusIs503() {
    assertThat(PkAuthPersistenceResponse.STATUS).isEqualTo(503);
  }

  @Test
  void bodyCarriesStableErrorCodeAndOperationInOrder() {
    PkAuthPersistenceException e =
        new PkAuthPersistenceException("credentials.save", "boom", new RuntimeException("boom"));

    var body = PkAuthPersistenceResponse.body(e);

    assertThat(body)
        .containsExactly(
            org.assertj.core.api.Assertions.entry("error", "persistence_failure"),
            org.assertj.core.api.Assertions.entry("operation", "credentials.save"));
  }
}
