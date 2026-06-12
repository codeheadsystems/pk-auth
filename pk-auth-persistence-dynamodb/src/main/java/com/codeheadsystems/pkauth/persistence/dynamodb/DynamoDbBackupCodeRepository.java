// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.Delete;
import software.amazon.awssdk.services.dynamodb.model.Put;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;

/** {@link BackupCodeRepository} backed by the single-table per ADR 0008. */
public final class DynamoDbBackupCodeRepository implements BackupCodeRepository {

  private final DynamoDbTable<BackupCodeItem> table;
  private final DynamoDbClient client;
  private final String tableName;

  public DynamoDbBackupCodeRepository(
      DynamoDbEnhancedClient enhanced, DynamoDbClient client, PkAuthDynamoTables tables) {
    Objects.requireNonNull(enhanced, "enhanced");
    Objects.requireNonNull(tables, "tables");
    this.client = Objects.requireNonNull(client, "client");
    this.tableName = tables.core();
    this.table = enhanced.table(tableName, TableSchema.fromBean(BackupCodeItem.class));
  }

  @Override
  public void save(StoredBackupCode code) {
    DynamoDbSupport.wrap(
        "backupCodes.save",
        () -> {
          table.putItem(BackupCodeItem.fromRecord(code));
          return null;
        });
  }

  @Override
  public List<StoredBackupCode> findByUserHandle(UserHandle userHandle) {
    return DynamoDbSupport.wrap(
        "backupCodes.findByUserHandle",
        () -> {
          String userB64 = Base64Url.encode(userHandle.value());
          return table
              .query(
                  QueryConditional.sortBeginsWith(
                      Key.builder()
                          .partitionValue(DynamoKeys.USER + userB64)
                          .sortValue(DynamoKeys.BACKUP)
                          .build()))
              .stream()
              .flatMap(page -> page.items().stream())
              .map(BackupCodeItem::toRecord)
              .toList();
        });
  }

  @Override
  public boolean consume(UserHandle userHandle, String codeId, Instant consumedAt) {
    return DynamoDbSupport.wrap(
        "backupCodes.consume",
        () -> {
          // Single conditional UpdateItem against the exact (pk, sk). No read, no scan. The
          // condition is the security-critical bit: two concurrent verifies both observing
          // consumed=false must NOT both succeed, or the single-use guarantee is broken.
          // attribute_exists(pk) prevents creating a phantom row if the (userHandle, codeId)
          // pair doesn't exist — matching the prior scan-found-nothing semantics.
          String userB64 = Base64Url.encode(userHandle.value());
          try {
            client.updateItem(
                UpdateItemRequest.builder()
                    .tableName(tableName)
                    .key(
                        Map.of(
                            "pk", AttributeValue.fromS(DynamoKeys.USER + userB64),
                            "sk", AttributeValue.fromS(DynamoKeys.BACKUP + codeId)))
                    .updateExpression("SET #c = :true, consumedAt = :consumedAt")
                    .conditionExpression("attribute_exists(pk) AND #c = :false")
                    .expressionAttributeNames(Map.of("#c", "consumed"))
                    .expressionAttributeValues(
                        Map.of(
                            ":true", AttributeValue.fromBool(true),
                            ":false", AttributeValue.fromBool(false),
                            ":consumedAt",
                                AttributeValue.fromS(DynamoDbSupport.encodeInstant(consumedAt))))
                    .build());
            return true;
          } catch (ConditionalCheckFailedException ignored) {
            // Either the code doesn't exist for this user, or it was already consumed by a
            // concurrent verify. Single-use guarantee preserved server-side; caller must treat
            // this as a verification miss to avoid minting two JWTs from one code.
            return false;
          }
        });
  }

  @Override
  public void deleteByUserHandle(UserHandle userHandle) {
    DynamoDbSupport.wrap(
        "backupCodes.deleteByUserHandle",
        () -> {
          String userB64 = Base64Url.encode(userHandle.value());
          table
              .query(
                  QueryConditional.sortBeginsWith(
                      Key.builder()
                          .partitionValue(DynamoKeys.USER + userB64)
                          .sortValue(DynamoKeys.BACKUP)
                          .build()))
              .stream()
              .flatMap(page -> page.items().stream())
              .forEach(
                  item ->
                      table.deleteItem(
                          Key.builder()
                              .partitionValue(item.getPk())
                              .sortValue(item.getSk())
                              .build()));
          return null;
        });
  }

  /**
   * Atomically replaces all backup codes for a user using a single {@code TransactWriteItems} call.
   * Existing rows are deleted and the new rows are inserted in one transaction; if the combined
   * item count exceeds DynamoDB's 100-item transaction limit an {@link IllegalArgumentException} is
   * thrown rather than degrading to a non-atomic fallback.
   *
   * @since 0.9.1
   */
  @Override
  public void replaceAll(UserHandle userHandle, List<StoredBackupCode> records) {
    Objects.requireNonNull(userHandle, "userHandle");
    Objects.requireNonNull(records, "records");
    String userB64 = Base64Url.encode(userHandle.value());
    String pk = DynamoKeys.USER + userB64;

    List<BackupCodeItem> existing =
        table
            .query(
                QueryConditional.sortBeginsWith(
                    Key.builder().partitionValue(pk).sortValue(DynamoKeys.BACKUP).build()))
            .stream()
            .flatMap(page -> page.items().stream())
            .toList();

    if (existing.isEmpty() && records.isEmpty()) {
      return;
    }

    int total = existing.size() + records.size();
    if (total > 100) {
      throw new IllegalArgumentException(
          "replaceAll would exceed DynamoDB TransactWriteItems limit of 100 items (existing="
              + existing.size()
              + ", new="
              + records.size()
              + ")");
    }

    List<TransactWriteItem> ops = new ArrayList<>(total);
    for (BackupCodeItem item : existing) {
      ops.add(
          TransactWriteItem.builder()
              .delete(
                  Delete.builder()
                      .tableName(tableName)
                      .key(
                          Map.of(
                              "pk", AttributeValue.fromS(item.getPk()),
                              "sk", AttributeValue.fromS(item.getSk())))
                      .build())
              .build());
    }
    for (StoredBackupCode code : records) {
      BackupCodeItem item = BackupCodeItem.fromRecord(code);
      Map<String, AttributeValue> values = new HashMap<>();
      values.put("pk", AttributeValue.fromS(item.getPk()));
      values.put("sk", AttributeValue.fromS(item.getSk()));
      values.put("entityType", AttributeValue.fromS(item.getEntityType()));
      values.put("codeId", AttributeValue.fromS(item.getCodeId()));
      values.put("userHandle", AttributeValue.fromS(item.getUserHandle()));
      values.put("hashedCode", AttributeValue.fromS(item.getHashedCode()));
      values.put("consumed", AttributeValue.fromBool(item.isConsumed()));
      if (item.getConsumedAt() != null) {
        values.put("consumedAt", AttributeValue.fromS(item.getConsumedAt()));
      }
      values.put("createdAt", AttributeValue.fromS(item.getCreatedAt()));
      ops.add(
          TransactWriteItem.builder()
              .put(Put.builder().tableName(tableName).item(values).build())
              .build());
    }

    client.transactWriteItems(TransactWriteItemsRequest.builder().transactItems(ops).build());
  }
}
