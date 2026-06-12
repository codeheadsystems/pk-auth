// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.spi.PkAuthPersistenceException;
import java.util.function.Supplier;
import software.amazon.awssdk.core.exception.SdkException;

/**
 * Internal helpers shared across the DynamoDB repositories. Package-private: this is not part of
 * the module's public surface.
 */
final class DynamoDbSupport {

  private DynamoDbSupport() {}

  /**
   * Runs {@code body} and wraps any {@link SdkException} in a {@link PkAuthPersistenceException} so
   * adapter exception mappers can produce a uniform 503. An already-wrapped {@link
   * PkAuthPersistenceException} (e.g. thrown by a nested call) propagates unchanged so its original
   * {@code op} context is preserved. Atomic-claim operations catch {@code
   * ConditionalCheckFailedException} inside {@code body} and translate it to a race/expiry result
   * before it can reach this wrapper.
   *
   * @param op short operation label carried on the wrapped exception.
   * @param body the persistence operation to run.
   * @param <T> the operation's return type.
   * @return whatever {@code body} returns.
   */
  static <T> T wrap(String op, Supplier<T> body) {
    try {
      return body.get();
    } catch (PkAuthPersistenceException already) {
      throw already;
    } catch (SdkException e) {
      throw new PkAuthPersistenceException(op, e.getMessage(), e);
    }
  }
}
