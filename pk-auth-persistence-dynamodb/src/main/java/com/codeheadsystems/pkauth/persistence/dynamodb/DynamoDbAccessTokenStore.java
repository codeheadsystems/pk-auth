// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.jwt.AccessTokenStore;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Expression;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.ScanEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

/**
 * {@link AccessTokenStore} backed by the {@code PkAuthCore} single table. Each issued JTI is
 * persisted as two items: a primary item keyed by jti (fast {@code exists} / {@code delete}) and a
 * user-indexed item (fast {@code deleteAllForUser}). DynamoDB's native TTL on the {@code ttl}
 * attribute prunes expired rows in the background; {@link #deleteExpiredBefore(Instant)} provides
 * synchronous cleanup for tests and operator workflows.
 *
 * <p>The two writes are non-atomic — primary first, then user-index. A failure between them leaves
 * the primary item live (validator-correct) and the user-index missing (a future deleteAllForUser
 * would not see this jti). Since user deletion is an operator-rare flow and the {@link
 * com.codeheadsystems.pkauth.lifecycle.UserDeletionListener} contract is idempotent, the operator
 * can retry. See ADR 0016.
 *
 * @since 1.1.0
 */
public final class DynamoDbAccessTokenStore implements AccessTokenStore {

  private final DynamoDbTable<AccessTokenItem> table;

  public DynamoDbAccessTokenStore(DynamoDbEnhancedClient enhanced, PkAuthDynamoTables tables) {
    Objects.requireNonNull(enhanced, "enhanced");
    Objects.requireNonNull(tables, "tables");
    this.table = enhanced.table(tables.core(), TableSchema.fromBean(AccessTokenItem.class));
  }

  @Override
  public void record(
      String jti,
      UserHandle userHandle,
      String audience,
      Optional<String> deviceId,
      Instant issuedAt,
      Instant expiresAt) {
    Objects.requireNonNull(jti, "jti");
    Objects.requireNonNull(userHandle, "userHandle");
    Objects.requireNonNull(audience, "audience");
    Objects.requireNonNull(deviceId, "deviceId");
    Objects.requireNonNull(issuedAt, "issuedAt");
    Objects.requireNonNull(expiresAt, "expiresAt");
    DynamoDbSupport.wrap(
        "access_tokens.record",
        () -> {
          String userB64 = Base64Url.encode(userHandle.value());
          long ttl = expiresAt.getEpochSecond();
          // Primary item (jti-keyed) — the load-bearing one for exists/validate.
          table.putItem(
              buildItem(
                  DynamoKeys.AT + jti,
                  DynamoKeys.AT + jti,
                  jti,
                  userB64,
                  audience,
                  deviceId.orElse(null),
                  issuedAt,
                  expiresAt,
                  ttl));
          // User-index item — for deleteAllForUser fan-out.
          table.putItem(
              buildItem(
                  DynamoKeys.USER + userB64,
                  DynamoKeys.AT + jti,
                  jti,
                  userB64,
                  audience,
                  deviceId.orElse(null),
                  issuedAt,
                  expiresAt,
                  ttl));
          return null;
        });
  }

  @Override
  public boolean exists(String jti) {
    if (jti == null) {
      return false;
    }
    return DynamoDbSupport.wrap(
        "access_tokens.exists",
        () ->
            table.getItem(
                    Key.builder()
                        .partitionValue(DynamoKeys.AT + jti)
                        .sortValue(DynamoKeys.AT + jti)
                        .build())
                != null);
  }

  @Override
  public boolean delete(UserHandle userHandle, String jti) {
    if (jti == null) {
      return false;
    }
    return DynamoDbSupport.wrap(
        "access_tokens.delete",
        () -> {
          AccessTokenItem primary =
              table.getItem(
                  Key.builder()
                      .partitionValue(DynamoKeys.AT + jti)
                      .sortValue(DynamoKeys.AT + jti)
                      .build());
          if (primary == null) {
            return false;
          }
          // Defense-in-depth ownership check — silent no-op on mismatch so callers can't probe
          // for jti existence across users.
          String ownerB64u = Base64Url.encode(userHandle.value());
          if (!ownerB64u.equals(primary.getUserHandleB64u())) {
            return false;
          }
          // Delete primary first — the load-bearing row for validation.
          table.deleteItem(
              Key.builder()
                  .partitionValue(DynamoKeys.AT + jti)
                  .sortValue(DynamoKeys.AT + jti)
                  .build());
          // Best-effort: delete the user-index pointer too. If this fails, native TTL or a
          // later deleteExpiredBefore will eventually clear it.
          table.deleteItem(
              Key.builder()
                  .partitionValue(DynamoKeys.USER + primary.getUserHandleB64u())
                  .sortValue(DynamoKeys.AT + jti)
                  .build());
          return true;
        });
  }

  @Override
  public int deleteAllForUser(UserHandle userHandle) {
    return DynamoDbSupport.wrap(
        "access_tokens.deleteAllForUser",
        () -> {
          String userB64 = Base64Url.encode(userHandle.value());
          int[] removed = {0};
          table
              .query(
                  QueryConditional.sortBeginsWith(
                      Key.builder()
                          .partitionValue(DynamoKeys.USER + userB64)
                          .sortValue(DynamoKeys.AT)
                          .build()))
              .stream()
              .flatMap(page -> page.items().stream())
              .forEach(
                  item -> {
                    String jti = item.getJti();
                    // Delete primary jti-keyed item first (load-bearing for validation).
                    table.deleteItem(
                        Key.builder()
                            .partitionValue(DynamoKeys.AT + jti)
                            .sortValue(DynamoKeys.AT + jti)
                            .build());
                    // Then the user-index pointer we found.
                    table.deleteItem(
                        Key.builder().partitionValue(item.getPk()).sortValue(item.getSk()).build());
                    removed[0]++;
                  });
          return removed[0];
        });
  }

  @Override
  public int deleteExpiredBefore(Instant before) {
    // DynamoDB's native TTL handles this asynchronously; the synchronous scan is for tests and
    // operator cleanup flows that need immediate, predictable removal.
    return DynamoDbSupport.wrap(
        "access_tokens.deleteExpiredBefore",
        () -> {
          long beforeEpoch = before.getEpochSecond();
          int[] removed = {0};
          // The server-side begins_with filter keeps non-AT# rows of the shared table off the wire;
          // a scan still consumes read capacity proportional to table size, so operators should
          // prefer native TTL and treat this as a test/maintenance path.
          table
              .scan(ScanEnhancedRequest.builder().filterExpression(primaryItemsOnly()).build())
              .items()
              .stream()
              .filter(item -> item.getPk() != null && item.getPk().startsWith(DynamoKeys.AT))
              .filter(item -> item.getPk().equals(item.getSk())) // primary items only
              .filter(item -> item.getTtl() != null && item.getTtl() < beforeEpoch)
              .forEach(
                  item -> {
                    String jti = item.getJti();
                    table.deleteItem(
                        Key.builder()
                            .partitionValue(DynamoKeys.AT + jti)
                            .sortValue(DynamoKeys.AT + jti)
                            .build());
                    if (item.getUserHandleB64u() != null) {
                      table.deleteItem(
                          Key.builder()
                              .partitionValue(DynamoKeys.USER + item.getUserHandleB64u())
                              .sortValue(DynamoKeys.AT + jti)
                              .build());
                    }
                    removed[0]++;
                  });
          return removed[0];
        });
  }

  private static AccessTokenItem buildItem(
      String pk,
      String sk,
      String jti,
      String userHandleB64u,
      String audience,
      String deviceId,
      Instant issuedAt,
      Instant expiresAt,
      long ttl) {
    AccessTokenItem item = new AccessTokenItem();
    item.setPk(pk);
    item.setSk(sk);
    item.setJti(jti);
    item.setUserHandleB64u(userHandleB64u);
    item.setAudience(audience);
    item.setDeviceId(deviceId);
    item.setIssuedAtIso(DynamoDbSupport.encodeInstant(issuedAt));
    item.setExpiresAtIso(DynamoDbSupport.encodeInstant(expiresAt));
    item.setTtl(ttl);
    return item;
  }

  /** Server-side filter restricting a table scan to AT# primary items (pk begins with AT#). */
  private static Expression primaryItemsOnly() {
    return Expression.builder()
        .expression("begins_with(pk, :atPrefix)")
        .putExpressionValue(":atPrefix", AttributeValue.fromS(DynamoKeys.AT))
        .build();
  }
}
