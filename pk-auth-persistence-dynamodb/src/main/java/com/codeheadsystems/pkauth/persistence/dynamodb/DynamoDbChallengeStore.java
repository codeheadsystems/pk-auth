// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.spi.ChallengeRecord;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ReturnValue;

/**
 * {@link ChallengeStore} backed by the {@code PkAuthCore} single-table. {@code takeOnce} is a
 * {@code DeleteItem} with {@code ReturnValues = ALL_OLD}, which is atomic.
 */
public final class DynamoDbChallengeStore implements ChallengeStore {

  private final DynamoDbClient client;
  private final String tableName;

  public DynamoDbChallengeStore(DynamoDbClient client, PkAuthDynamoTables tables) {
    this.client = Objects.requireNonNull(client, "client");
    this.tableName = Objects.requireNonNull(tables, "tables").core();
  }

  @Override
  public void put(ChallengeId id, ChallengeRecord record, Duration ttl) {
    Objects.requireNonNull(id, "id");
    Objects.requireNonNull(record, "record");
    Objects.requireNonNull(ttl, "ttl");
    if (ttl.isZero() || ttl.isNegative()) {
      throw new IllegalArgumentException("ttl must be strictly positive, got " + ttl);
    }
    DynamoDbSupport.wrap(
        "challenges.put",
        () -> {
          ChallengeItem item = ChallengeItem.build(id, record);
          Map<String, AttributeValue> values = new HashMap<>();
          values.put("pk", AttributeValue.fromS(item.getPk()));
          values.put("sk", AttributeValue.fromS(item.getSk()));
          values.put("entityType", AttributeValue.fromS(item.getEntityType()));
          values.put("ttl", AttributeValue.fromN(Long.toString(item.getTtl())));
          values.put("challenge", AttributeValue.fromS(item.getChallenge()));
          values.put("purpose", AttributeValue.fromS(item.getPurpose()));
          if (item.getUserHandle() != null) {
            values.put("userHandle", AttributeValue.fromS(item.getUserHandle()));
          }
          values.put("expiresAt", AttributeValue.fromN(Long.toString(item.getExpiresAt())));
          client.putItem(PutItemRequest.builder().tableName(tableName).item(values).build());
          return null;
        });
  }

  @Override
  public Optional<ChallengeRecord> takeOnce(ChallengeId id) {
    return DynamoDbSupport.wrap(
        "challenges.takeOnce",
        () -> {
          Map<String, AttributeValue> key = new HashMap<>();
          key.put("pk", AttributeValue.fromS(DynamoKeys.CHAL + id.value()));
          key.put("sk", AttributeValue.fromS("META"));
          // Server-side expiry: refuse to delete a row that's already past its expiresAt timestamp.
          // expiresAt is stored as a numeric epoch-millis attribute so DynamoDB's numeric
          // comparator gives precise (sub-second) ordering against the wall clock. DynamoDB's
          // attribute-level TTL deletion is best-effort (can lag up to ~48h), so it cannot be
          // relied on for security expiry — this condition is what actually enforces single-use
          // within the TTL window.
          software.amazon.awssdk.services.dynamodb.model.DeleteItemResponse response;
          try {
            response =
                client.deleteItem(
                    DeleteItemRequest.builder()
                        .tableName(tableName)
                        .key(key)
                        .conditionExpression("expiresAt > :now")
                        .expressionAttributeValues(
                            Map.of(
                                ":now",
                                AttributeValue.fromN(Long.toString(Instant.now().toEpochMilli()))))
                        .returnValues(ReturnValue.ALL_OLD)
                        .build());
          } catch (ConditionalCheckFailedException expired) {
            // Row exists but is past expiry, OR the row simply doesn't exist (DynamoDB raises the
            // same exception in both cases when a condition expression references a missing
            // attribute). Either way, no challenge is consumed.
            return Optional.empty();
          }
          if (response.attributes() == null || response.attributes().isEmpty()) {
            return Optional.empty();
          }
          Map<String, AttributeValue> attrs = response.attributes();
          ChallengeItem item = new ChallengeItem();
          item.setPk(attrs.get("pk").s());
          item.setSk(attrs.get("sk").s());
          item.setEntityType(attrs.get("entityType").s());
          item.setChallenge(attrs.get("challenge").s());
          item.setPurpose(attrs.get("purpose").s());
          if (attrs.containsKey("userHandle")) {
            item.setUserHandle(attrs.get("userHandle").s());
          }
          item.setExpiresAt(Long.parseLong(attrs.get("expiresAt").n()));
          return Optional.of(item.toRecord());
        });
  }
}
