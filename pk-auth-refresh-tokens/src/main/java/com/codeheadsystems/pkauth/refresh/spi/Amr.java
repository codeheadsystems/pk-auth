// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh.spi;

import java.util.List;
import org.jspecify.annotations.Nullable;

/**
 * Storage codec for the RFC 8176 {@code amr} (authentication method references) list carried on a
 * {@link com.codeheadsystems.pkauth.refresh.RefreshTokenRecord}. Persistence adapters store the
 * list as a single comma-separated column/attribute; this codec is the one place that encoding
 * lives so the JDBI and DynamoDB implementations cannot silently diverge.
 *
 * <p>The comma separator is safe because {@code RefreshTokenRecord} rejects any {@code amr} entry
 * containing a {@code ','} at construction time, so a round-trip is lossless.
 *
 * @since 2.0.0
 */
public final class Amr {

  /** The generic fallback returned for rows persisted before an {@code amr} column/attribute. */
  private static final List<String> DEFAULT = List.of("user");

  private Amr() {}

  /**
   * Encodes the {@code amr} references for storage as a single comma-separated string.
   *
   * @param amr the non-empty, comma-free references from a {@code RefreshTokenRecord}.
   * @return the comma-joined storage form.
   * @since 2.0.0
   */
  public static String encode(List<String> amr) {
    return String.join(",", amr);
  }

  /**
   * Decodes the stored comma-separated {@code amr} string back into a list. A {@code null} or blank
   * value — a row written before the {@code amr} column/attribute existed — maps to the generic
   * {@code ["user"]} so older tokens still satisfy the record's non-empty contract.
   *
   * @param stored the stored comma-separated value, possibly {@code null} or blank.
   * @return the decoded references, never empty.
   * @since 2.0.0
   */
  public static List<String> decode(@Nullable String stored) {
    if (stored == null || stored.isBlank()) {
      return DEFAULT;
    }
    return List.of(stored.split(","));
  }
}
