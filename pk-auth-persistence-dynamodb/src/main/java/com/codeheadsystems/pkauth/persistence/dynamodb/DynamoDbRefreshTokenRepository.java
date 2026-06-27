// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.refresh.RefreshTokenConfig;
import com.codeheadsystems.pkauth.refresh.RefreshTokenRecord;
import com.codeheadsystems.pkauth.refresh.RevokeReason;
import com.codeheadsystems.pkauth.refresh.spi.Amr;
import com.codeheadsystems.pkauth.refresh.spi.RefreshTokenRepository;
import com.codeheadsystems.pkauth.spi.PkAuthPersistenceException;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Expression;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.IgnoreNullsMode;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.ScanEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.TransactPutItemEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.TransactUpdateItemEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.TransactWriteItemsEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.UpdateItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.CancellationReason;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.TransactionCanceledException;

/**
 * {@link RefreshTokenRepository} backed by the {@code PkAuthCore} single table. The load-bearing
 * {@link #rotateAtomically} primitive uses {@code TransactWriteItems} to commit "mark parent used"
 * and "insert successor" as a single atomic operation — without that, a concurrent replay-revoker
 * could miss the freshly-inserted successor.
 *
 * <p>Each issued JTI lives at up to three item addresses (primary + user-index + family-index) —
 * the user-index and family-index items aren't load-bearing for correctness (the primary item is
 * the authority on used/revoked state) but they make {@code revokeAllForUser} and {@code
 * revokeFamily} O(family-size) rather than full-table scans.
 *
 * <p>Native DynamoDB TTL on the {@code ttl} attribute prunes rows in the background; {@link
 * #deleteExpiredBefore(Instant)} provides synchronous cleanup for tests and operator workflows.
 *
 * @since 1.1.0
 */
public final class DynamoDbRefreshTokenRepository implements RefreshTokenRepository {

  private static final String FAMILY_PK_PREFIX = DynamoKeys.RTF;
  private static final String USER_PK_PREFIX = DynamoKeys.USER;
  // PRIMARY_PK_PREFIX and INDEX_SK_PREFIX intentionally share the same DynamoKeys.RT value: the
  // primary item's partition key and the jti-index's sort key both namespace on "RT#". They are
  // named separately because they play distinct roles in the single-table layout.
  private static final String PRIMARY_PK_PREFIX = DynamoKeys.RT;
  private static final String INDEX_SK_PREFIX = DynamoKeys.RT;
  // DynamoDB's code() for a cancellation reason whose ConditionExpression evaluated false.
  private static final String CONDITIONAL_CHECK_FAILED = "ConditionalCheckFailed";

  private final DynamoDbEnhancedClient enhanced;
  private final DynamoDbTable<RefreshTokenItem> table;
  private final Duration cleanupRetention;

  /**
   * Uses the {@linkplain RefreshTokenConfig#DEFAULT_CLEANUP_RETENTION default 30-day} forensic
   * retention window for the native-TTL prune timestamp.
   */
  public DynamoDbRefreshTokenRepository(
      DynamoDbEnhancedClient enhanced, PkAuthDynamoTables tables) {
    this(enhanced, tables, RefreshTokenConfig.DEFAULT_CLEANUP_RETENTION);
  }

  /**
   * @param cleanupRetention how long past {@code expiresAt} the native {@code ttl} attribute keeps
   *     a row before DynamoDB prunes it — must match the {@link
   *     RefreshTokenConfig#cleanupRetention()} the host runs the service with, so the background
   *     sweep honors the same forensic window the JDBI backend does.
   */
  public DynamoDbRefreshTokenRepository(
      DynamoDbEnhancedClient enhanced, PkAuthDynamoTables tables, Duration cleanupRetention) {
    this.enhanced = Objects.requireNonNull(enhanced, "enhanced");
    Objects.requireNonNull(tables, "tables");
    this.cleanupRetention = Objects.requireNonNull(cleanupRetention, "cleanupRetention");
    this.table = enhanced.table(tables.core(), TableSchema.fromBean(RefreshTokenItem.class));
  }

  @Override
  public void create(RefreshTokenRecord record) {
    Objects.requireNonNull(record, "record");
    DynamoDbSupport.wrap(
        "refresh_tokens.create",
        () -> {
          // Write the primary item plus its user-index and family-index pointers as a single atomic
          // TransactWriteItems — the same idiom rotateAtomically uses. If any of the three puts
          // fails
          // (throttle/crash) none commit, so a breach-response revokeFamily/revokeAllForUser (which
          // scan the index pointers) can never miss an orphaned primary whose index entries were
          // never written. The primary carries an attribute_not_exists(pk) guard so a duplicate
          // refreshId is rejected; the two index items are unconditional puts but ride the same
          // transaction.
          String userB64 = Base64Url.encode(record.userHandle().value());
          RefreshTokenItem primary =
              toItem(
                  record,
                  PRIMARY_PK_PREFIX + record.refreshId(),
                  PRIMARY_PK_PREFIX + record.refreshId());
          RefreshTokenItem userIndex =
              toItem(record, USER_PK_PREFIX + userB64, INDEX_SK_PREFIX + record.refreshId());
          RefreshTokenItem familyIndex =
              toItem(
                  record,
                  FAMILY_PK_PREFIX + record.familyId(),
                  INDEX_SK_PREFIX + record.refreshId());
          try {
            enhanced.transactWriteItems(
                TransactWriteItemsEnhancedRequest.builder()
                    .addPutItem(
                        table,
                        TransactPutItemEnhancedRequest.builder(RefreshTokenItem.class)
                            .item(primary)
                            .conditionExpression(
                                Expression.builder().expression("attribute_not_exists(pk)").build())
                            .build())
                    .addPutItem(table, userIndex)
                    .addPutItem(table, familyIndex)
                    .build());
          } catch (TransactionCanceledException cancelled) {
            // The primary's attribute_not_exists(pk) guard is the first action added (index 0); a
            // ConditionalCheckFailed there means the refreshId already exists. Surface it as the
            // same
            // duplicate signal create() has always produced, but routed through
            // DynamoDbSupport.wrap
            // as a PkAuthPersistenceException like every other failure in this class — rather than
            // as
            // a raw IllegalStateException that bypassed the wrapper. Any other cancellation
            // (throughput, transaction conflict, validation) is rethrown for the wrapper to map.
            if (isPrimaryDuplicate(cancelled)) {
              throw new PkAuthPersistenceException(
                  "refresh_tokens.create", "duplicate refreshId: " + record.refreshId(), cancelled);
            }
            throw cancelled;
          }
          return null;
        });
  }

  @Override
  public Optional<RefreshTokenRecord> findByRefreshId(String refreshId) {
    return DynamoDbSupport.wrap(
        "refresh_tokens.findByRefreshId",
        () -> {
          RefreshTokenItem item =
              table.getItem(
                  Key.builder()
                      .partitionValue(PRIMARY_PK_PREFIX + refreshId)
                      .sortValue(PRIMARY_PK_PREFIX + refreshId)
                      .build());
          return Optional.ofNullable(item).map(DynamoDbRefreshTokenRepository::toRecord);
        });
  }

  @Override
  public boolean rotateAtomically(
      String parentRefreshId, Instant now, RefreshTokenRecord successor) {
    Objects.requireNonNull(parentRefreshId, "parentRefreshId");
    Objects.requireNonNull(now, "now");
    Objects.requireNonNull(successor, "successor");
    return DynamoDbSupport.wrap(
        "refresh_tokens.rotateAtomically",
        () -> {
          // Mark the parent's primary item used via a conditional UpdateItem that touches ONLY
          // used_at (ignoreNulls) — not a read-modify-write of the whole item — so a concurrent
          // writer to any other parent attribute can never be clobbered, and no prior read is
          // needed. The successor's user-index partition is derived from the successor's own
          // userHandle, not the parent's, so the parent never has to be loaded.
          //
          // The condition is the authoritative freshness check: the parent must exist
          // (attribute_exists(pk) — UpdateItem would otherwise upsert a brand-new row) and be
          // unused, unrevoked, and unexpired. Expiry compares the numeric epoch-second
          // `expiresAtEpoch` attribute (== expiresAt.epochSecond), NOT the ISO string:
          // Instant.toString() is variable-precision (it drops the fractional-seconds field when
          // zero), so a lexicographic ">" sorts "...:00Z" after "...:00.000001Z" and would treat an
          // expired token as still fresh. The separate `ttl` attribute carries
          // expiresAt + cleanupRetention for native pruning and must NOT be used for freshness.
          RefreshTokenItem parentMark = new RefreshTokenItem();
          parentMark.setPk(PRIMARY_PK_PREFIX + parentRefreshId);
          parentMark.setSk(PRIMARY_PK_PREFIX + parentRefreshId);
          parentMark.setUsedAtIso(DynamoDbSupport.encodeInstant(now));

          Expression freshness =
              Expression.builder()
                  .expression(
                      "attribute_exists(pk) AND attribute_not_exists(usedAtIso)"
                          + " AND attribute_not_exists(revokedAtIso) AND #expEpoch > :nowEpoch")
                  .putExpressionName("#expEpoch", "expiresAtEpoch")
                  .putExpressionValue(
                      ":nowEpoch", AttributeValue.fromN(Long.toString(now.getEpochSecond())))
                  .build();

          // Build the three successor items.
          RefreshTokenItem successorPrimary =
              toItem(
                  successor,
                  PRIMARY_PK_PREFIX + successor.refreshId(),
                  PRIMARY_PK_PREFIX + successor.refreshId());
          RefreshTokenItem successorUser =
              toItem(
                  successor,
                  USER_PK_PREFIX + successorUserB64(successor),
                  INDEX_SK_PREFIX + successor.refreshId());
          RefreshTokenItem successorFamily =
              toItem(
                  successor,
                  FAMILY_PK_PREFIX + successor.familyId(),
                  INDEX_SK_PREFIX + successor.refreshId());

          try {
            enhanced.transactWriteItems(
                TransactWriteItemsEnhancedRequest.builder()
                    .addUpdateItem(
                        table,
                        TransactUpdateItemEnhancedRequest.builder(RefreshTokenItem.class)
                            .item(parentMark)
                            .ignoreNullsMode(IgnoreNullsMode.SCALAR_ONLY)
                            .conditionExpression(freshness)
                            .build())
                    .addPutItem(
                        table,
                        TransactPutItemEnhancedRequest.builder(RefreshTokenItem.class)
                            .item(successorPrimary)
                            .conditionExpression(
                                Expression.builder().expression("attribute_not_exists(pk)").build())
                            .build())
                    .addPutItem(table, successorUser)
                    .addPutItem(table, successorFamily)
                    .build());
            return true;
          } catch (TransactionCanceledException cancelled) {
            // Distinguish a genuine freshness-condition failure (the parent was already used,
            // revoked, or expired — a real replay/race that SHOULD return false and let the caller
            // scorch the family) from a transient cancellation (throughput, transaction conflict,
            // validation). Only the former is "race lost". Surfacing the latter as false would let
            // a momentary throughput blip be misread as a replay and silently revoke a legitimate
            // token family; rethrowing instead maps it (via DynamoDbSupport.wrap) to a 5xx the
            // client can retry. When the reason is undeterminable, fail closed by rethrowing.
            if (isParentFreshnessFailure(cancelled)) {
              return false;
            }
            throw cancelled;
          }
        });
  }

  /**
   * True only when the {@code rotateAtomically} transaction was cancelled because the parent's
   * freshness condition failed — the legitimate replay/race signal. The parent's conditional {@code
   * UpdateItem} is the first action added to the transaction, so its reason is at index 0; a {@code
   * ConditionalCheckFailed} code there means the parent was already used, revoked, or expired. Any
   * other cancellation reason (throughput, transaction conflict, validation) is transient and
   * returns false here so the caller rethrows rather than scorching the family.
   */
  private static boolean isParentFreshnessFailure(TransactionCanceledException cancelled) {
    List<CancellationReason> reasons = cancelled.cancellationReasons();
    if (reasons == null || reasons.isEmpty()) {
      return false;
    }
    return CONDITIONAL_CHECK_FAILED.equals(reasons.get(0).code());
  }

  /**
   * True only when the {@code create} transaction was cancelled because the primary item's {@code
   * attribute_not_exists(pk)} guard failed — i.e. the refreshId already exists. The primary {@code
   * Put} is the first action added to the transaction, so its reason is at index 0; a {@code
   * ConditionalCheckFailed} code there is the duplicate signal. Any other cancellation reason
   * (throughput, transaction conflict, validation) is transient and is rethrown by the caller for
   * {@code DynamoDbSupport.wrap} to map.
   */
  private static boolean isPrimaryDuplicate(TransactionCanceledException cancelled) {
    List<CancellationReason> reasons = cancelled.cancellationReasons();
    if (reasons == null || reasons.isEmpty()) {
      return false;
    }
    return CONDITIONAL_CHECK_FAILED.equals(reasons.get(0).code());
  }

  @Override
  public int revokeFamily(String familyId, Instant now, RevokeReason reason) {
    return DynamoDbSupport.wrap(
        "refresh_tokens.revokeFamily",
        () -> {
          // Query the family-index for every member, then mark the primary item of each revoked
          // (the primary is the authority on revoked_at).
          int[] revoked = {0};
          String nowIso = DynamoDbSupport.encodeInstant(now);
          table
              .query(
                  QueryConditional.sortBeginsWith(
                      Key.builder()
                          .partitionValue(FAMILY_PK_PREFIX + familyId)
                          .sortValue(INDEX_SK_PREFIX)
                          .build()))
              .stream()
              .flatMap(p -> p.items().stream())
              .forEach(indexItem -> revoked[0] += markRevoked(indexItem, nowIso, reason));
          return revoked[0];
        });
  }

  @Override
  public int revokeAllForUser(UserHandle userHandle, Instant now, RevokeReason reason) {
    return DynamoDbSupport.wrap(
        "refresh_tokens.revokeAllForUser",
        () -> {
          String userB64 = Base64Url.encode(userHandle.value());
          int[] revoked = {0};
          String nowIso = DynamoDbSupport.encodeInstant(now);
          table
              .query(
                  QueryConditional.sortBeginsWith(
                      Key.builder()
                          .partitionValue(USER_PK_PREFIX + userB64)
                          .sortValue(INDEX_SK_PREFIX)
                          .build()))
              .stream()
              .flatMap(p -> p.items().stream())
              .forEach(indexItem -> revoked[0] += markRevoked(indexItem, nowIso, reason));
          return revoked[0];
        });
  }

  /**
   * Marks one family/user-index member's primary item revoked via a conditional, scalar-only {@code
   * UpdateItem} that writes ONLY {@code revokedAtIso}/{@code revokedReason} — never a
   * read-modify-write of the whole item. A full-item {@code putItem} (the prior approach) would
   * carry a stale snapshot and could silently revert a {@code usedAtIso} mark set concurrently by
   * {@code rotateAtomically}, corrupting the rotation/audit trail. {@code attribute_exists(pk)}
   * prevents resurrecting a primary that was already pruned (an index row can outlive it), and
   * {@code attribute_not_exists(revokedAtIso)} keeps the operation idempotent under concurrent
   * revokers. A failed condition (already revoked, or primary gone) means "nothing to do" and
   * returns 0.
   *
   * @return 1 if this call set revoked_at, 0 if there was nothing to revoke
   */
  private int markRevoked(RefreshTokenItem indexItem, String nowIso, RevokeReason reason) {
    RefreshTokenItem mark = new RefreshTokenItem();
    mark.setPk(PRIMARY_PK_PREFIX + indexItem.getRefreshId());
    mark.setSk(PRIMARY_PK_PREFIX + indexItem.getRefreshId());
    mark.setRevokedAtIso(nowIso);
    mark.setRevokedReason(reason.name());
    try {
      table.updateItem(
          UpdateItemEnhancedRequest.builder(RefreshTokenItem.class)
              .item(mark)
              .ignoreNullsMode(IgnoreNullsMode.SCALAR_ONLY)
              .conditionExpression(
                  Expression.builder()
                      .expression("attribute_exists(pk) AND attribute_not_exists(revokedAtIso)")
                      .build())
              .build());
      return 1;
    } catch (ConditionalCheckFailedException raceLost) {
      // Already revoked by another revoker, or the primary was pruned — nothing to do.
      return 0;
    }
  }

  @Override
  public List<RefreshTokenRecord> findByUserHandle(UserHandle userHandle) {
    return DynamoDbSupport.wrap(
        "refresh_tokens.findByUserHandle",
        () -> {
          String userB64 = Base64Url.encode(userHandle.value());
          // Query the user-index for refreshIds, then load each primary item for authoritative
          // used/revoked state.
          Map<String, RefreshTokenRecord> byId = new LinkedHashMap<>();
          table
              .query(
                  QueryConditional.sortBeginsWith(
                      Key.builder()
                          .partitionValue(USER_PK_PREFIX + userB64)
                          .sortValue(INDEX_SK_PREFIX)
                          .build()))
              .stream()
              .flatMap(p -> p.items().stream())
              .forEach(
                  indexItem -> {
                    RefreshTokenItem primary =
                        table.getItem(
                            Key.builder()
                                .partitionValue(PRIMARY_PK_PREFIX + indexItem.getRefreshId())
                                .sortValue(PRIMARY_PK_PREFIX + indexItem.getRefreshId())
                                .build());
                    if (primary != null) {
                      byId.put(primary.getRefreshId(), toRecord(primary));
                    }
                  });
          return List.copyOf(byId.values());
        });
  }

  @Override
  public List<RefreshTokenRecord> findByFamilyId(String familyId) {
    return DynamoDbSupport.wrap(
        "refresh_tokens.findByFamilyId",
        () -> {
          Map<String, RefreshTokenRecord> byId = new LinkedHashMap<>();
          table
              .query(
                  QueryConditional.sortBeginsWith(
                      Key.builder()
                          .partitionValue(FAMILY_PK_PREFIX + familyId)
                          .sortValue(INDEX_SK_PREFIX)
                          .build()))
              .stream()
              .flatMap(p -> p.items().stream())
              .forEach(
                  indexItem -> {
                    RefreshTokenItem primary =
                        table.getItem(
                            Key.builder()
                                .partitionValue(PRIMARY_PK_PREFIX + indexItem.getRefreshId())
                                .sortValue(PRIMARY_PK_PREFIX + indexItem.getRefreshId())
                                .build());
                    if (primary != null) {
                      byId.put(primary.getRefreshId(), toRecord(primary));
                    }
                  });
          return List.copyOf(byId.values());
        });
  }

  @Override
  public int deleteExpiredBefore(Instant cutoff) {
    return DynamoDbSupport.wrap(
        "refresh_tokens.deleteExpiredBefore",
        () -> {
          long cutoffEpoch = cutoff.getEpochSecond();
          int[] removed = {0};
          // Scan only primary items (pk and sk both start with RT#) and filter by the
          // retention predicate that mirrors the JDBI cleanup SQL (expires_at < cutoff). This uses
          // `expiresAtEpoch`, NOT the retention-extended `ttl` attribute. The server-side
          // begins_with filter keeps non-RT# rows of the shared table off the wire; note a scan
          // still consumes read capacity proportional to table size, so operators should prefer
          // native TTL and treat this as a test/maintenance path.
          table
              .scan(ScanEnhancedRequest.builder().filterExpression(primaryItemsOnly()).build())
              .items()
              .stream()
              .filter(item -> item.getPk() != null && item.getPk().startsWith(PRIMARY_PK_PREFIX))
              .filter(item -> item.getPk().equals(item.getSk())) // primary only
              .filter(
                  item ->
                      item.getExpiresAtEpoch() != null && item.getExpiresAtEpoch() < cutoffEpoch)
              .filter(
                  item ->
                      (item.getUsedAtIso() != null
                              && DynamoDbSupport.parseInstant(item.getUsedAtIso()).isBefore(cutoff))
                          || (item.getRevokedAtIso() != null
                              && DynamoDbSupport.parseInstant(item.getRevokedAtIso())
                                  .isBefore(cutoff)))
              .forEach(
                  item -> {
                    deleteAllItems(item);
                    removed[0]++;
                  });
          return removed[0];
        });
  }

  // -- Internals --------------------------------------------------------------------------

  private void deleteAllItems(RefreshTokenItem primary) {
    String refreshId = primary.getRefreshId();
    table.deleteItem(
        Key.builder()
            .partitionValue(PRIMARY_PK_PREFIX + refreshId)
            .sortValue(PRIMARY_PK_PREFIX + refreshId)
            .build());
    if (primary.getUserHandleB64u() != null) {
      table.deleteItem(
          Key.builder()
              .partitionValue(USER_PK_PREFIX + primary.getUserHandleB64u())
              .sortValue(INDEX_SK_PREFIX + refreshId)
              .build());
    }
    if (primary.getFamilyId() != null) {
      table.deleteItem(
          Key.builder()
              .partitionValue(FAMILY_PK_PREFIX + primary.getFamilyId())
              .sortValue(INDEX_SK_PREFIX + refreshId)
              .build());
    }
  }

  private static String successorUserB64(RefreshTokenRecord r) {
    return Base64Url.encode(r.userHandle().value());
  }

  private RefreshTokenItem toItem(RefreshTokenRecord r, String pk, String sk) {
    RefreshTokenItem item = new RefreshTokenItem();
    item.setPk(pk);
    item.setSk(sk);
    item.setRefreshId(r.refreshId());
    item.setTokenHashB64u(Base64Url.encode(r.tokenHash()));
    item.setUserHandleB64u(Base64Url.encode(r.userHandle().value()));
    item.setAudience(r.audience());
    item.setDeviceId(r.deviceId().orElse(null));
    item.setFamilyId(r.familyId());
    item.setParentRefreshId(r.parentRefreshId().orElse(null));
    item.setIssuedAtIso(DynamoDbSupport.encodeInstant(r.issuedAt()));
    item.setExpiresAtIso(DynamoDbSupport.encodeInstant(r.expiresAt()));
    item.setUsedAtIso(r.usedAt().map(DynamoDbSupport::encodeInstant).orElse(null));
    item.setRevokedAtIso(r.revokedAt().map(DynamoDbSupport::encodeInstant).orElse(null));
    item.setRevokedReason(r.revokedReason().map(Enum::name).orElse(null));
    item.setAmr(Amr.encode(r.amr()));
    item.setExpiresAtEpoch(r.expiresAt().getEpochSecond());
    item.setTtl(r.expiresAt().plus(cleanupRetention).getEpochSecond());
    return item;
  }

  private static RefreshTokenRecord toRecord(RefreshTokenItem item) {
    byte[] hash = Base64Url.decode(item.getTokenHashB64u());
    return new RefreshTokenRecord(
        item.getRefreshId(),
        hash,
        UserHandle.of(Base64Url.decode(item.getUserHandleB64u())),
        item.getAudience(),
        Optional.ofNullable(item.getDeviceId()),
        item.getFamilyId(),
        Optional.ofNullable(item.getParentRefreshId()),
        DynamoDbSupport.parseInstant(item.getIssuedAtIso()),
        DynamoDbSupport.parseInstant(item.getExpiresAtIso()),
        Optional.ofNullable(item.getUsedAtIso()).map(Instant::parse),
        Optional.ofNullable(item.getRevokedAtIso()).map(Instant::parse),
        Optional.ofNullable(item.getRevokedReason()).map(RevokeReason::valueOf),
        Amr.decode(item.getAmr()));
  }

  /** Server-side filter restricting a table scan to RT# primary items (pk begins with RT#). */
  private static Expression primaryItemsOnly() {
    return Expression.builder()
        .expression("begins_with(pk, :rtPrefix)")
        .putExpressionValue(":rtPrefix", AttributeValue.fromS(PRIMARY_PK_PREFIX))
        .build();
  }
}
