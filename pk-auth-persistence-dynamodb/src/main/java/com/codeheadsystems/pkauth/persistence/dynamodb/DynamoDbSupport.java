// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.spi.PkAuthPersistenceException;
import java.time.Instant;
import java.util.function.Supplier;
import org.jspecify.annotations.Nullable;
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

  /**
   * Encodes an {@link Instant} to its ISO-8601 storage form. This is the single definition of the
   * table's instant encoding; it is deliberately {@link Instant#toString()} so existing rows remain
   * readable (see {@code RefreshTokenItem} for why ordering still uses epoch seconds, not this).
   *
   * @param instant the instant to encode.
   * @return the ISO-8601 string stored on the item.
   */
  static String encodeInstant(Instant instant) {
    return instant.toString();
  }

  /** Nullable variant of {@link #encodeInstant(Instant)}; {@code null} encodes to {@code null}. */
  static @Nullable String encodeInstantOrNull(@Nullable Instant instant) {
    return instant == null ? null : instant.toString();
  }

  /**
   * Parses an ISO-8601 storage string back into an {@link Instant}. The inverse of {@link
   * #encodeInstant(Instant)}.
   *
   * @param iso the stored ISO-8601 string.
   * @return the decoded instant.
   */
  static Instant parseInstant(String iso) {
    return Instant.parse(iso);
  }

  /** Nullable variant of {@link #parseInstant(String)}; {@code null} decodes to {@code null}. */
  static @Nullable Instant parseInstantOrNull(@Nullable String iso) {
    return iso == null ? null : Instant.parse(iso);
  }
}
