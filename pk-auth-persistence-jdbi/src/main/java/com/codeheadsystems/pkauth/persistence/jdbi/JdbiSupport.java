// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import com.codeheadsystems.pkauth.spi.PkAuthPersistenceException;
import java.util.function.Supplier;
import org.jdbi.v3.core.JdbiException;

/**
 * Internal helpers shared across the JDBI repositories. Package-private: this is not part of the
 * module's public surface.
 */
final class JdbiSupport {

  private JdbiSupport() {}

  /**
   * Runs {@code body} and wraps any {@link JdbiException} in a {@link PkAuthPersistenceException}
   * so adapter exception mappers can produce a uniform 503. An already-wrapped {@link
   * PkAuthPersistenceException} (e.g. thrown by a nested call) propagates unchanged so its original
   * {@code op} context is preserved.
   *
   * @param op short operation label carried on the wrapped exception (never the raw SQL).
   * @param body the persistence operation to run.
   * @param <T> the operation's return type.
   * @return whatever {@code body} returns.
   */
  static <T> T wrap(String op, Supplier<T> body) {
    try {
      return body.get();
    } catch (PkAuthPersistenceException already) {
      throw already;
    } catch (JdbiException e) {
      throw new PkAuthPersistenceException(op, e.getMessage(), e);
    }
  }
}
