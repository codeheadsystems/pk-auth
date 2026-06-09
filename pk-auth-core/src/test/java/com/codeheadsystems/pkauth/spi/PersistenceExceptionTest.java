// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** Constructors and the {@code operation()} tag on the persistence exception hierarchy. */
class PersistenceExceptionTest {

  @Test
  void persistenceExceptionCarriesOperationMessageAndCause() {
    Throwable cause = new IllegalStateException("db down");
    PkAuthPersistenceException ex =
        new PkAuthPersistenceException("credentials.save", "save failed", cause);
    assertThat(ex.operation()).isEqualTo("credentials.save");
    assertThat(ex.getMessage()).isEqualTo("save failed");
    assertThat(ex.getCause()).isSameAs(cause);
  }

  @Test
  void persistenceExceptionTwoArgConstructorHasNoCause() {
    PkAuthPersistenceException ex = new PkAuthPersistenceException("challenges.put", "put failed");
    assertThat(ex.operation()).isEqualTo("challenges.put");
    assertThat(ex.getCause()).isNull();
  }

  @Test
  void duplicateCredentialExceptionPinsOperationToCredentialsSave() {
    DuplicateCredentialException ex = new DuplicateCredentialException("already exists");
    assertThat(ex.operation()).isEqualTo("credentials.save");
    assertThat(ex.getMessage()).isEqualTo("already exists");
    assertThat(ex).isInstanceOf(PkAuthPersistenceException.class);

    Throwable cause = new RuntimeException("unique violation");
    DuplicateCredentialException withCause = new DuplicateCredentialException("dup", cause);
    assertThat(withCause.getCause()).isSameAs(cause);
    assertThat(withCause.operation()).isEqualTo("credentials.save");
  }
}
