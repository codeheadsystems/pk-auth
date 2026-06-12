// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.ReturnValue;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemResponse;

/** {@link OtpRepository} backed by the single-table per ADR 0008. */
public final class DynamoDbOtpRepository implements OtpRepository {

  private final DynamoDbTable<OtpItem> table;
  private final DynamoDbClient client;
  private final String tableName;

  public DynamoDbOtpRepository(
      DynamoDbEnhancedClient enhanced, DynamoDbClient client, PkAuthDynamoTables tables) {
    Objects.requireNonNull(enhanced, "enhanced");
    Objects.requireNonNull(tables, "tables");
    this.client = Objects.requireNonNull(client, "client");
    this.tableName = tables.core();
    this.table = enhanced.table(tableName, TableSchema.fromBean(OtpItem.class));
  }

  @Override
  public void save(StoredOtp otp) {
    DynamoDbSupport.wrap(
        "otp.save",
        () -> {
          table.putItem(OtpItem.fromRecord(otp));
          return null;
        });
  }

  @Override
  public Optional<StoredOtp> findLatestActive(UserHandle userHandle, String phoneE164) {
    return DynamoDbSupport.wrap(
        "otp.findLatestActive",
        () -> {
          String userB64 = Base64Url.encode(userHandle.value());
          return table
              .query(
                  QueryConditional.sortBeginsWith(
                      Key.builder().partitionValue("USER#" + userB64).sortValue("OTP#").build()))
              .stream()
              .flatMap(page -> page.items().stream())
              .filter(i -> phoneE164.equals(i.getPhoneE164()))
              .filter(i -> !i.isConsumed())
              .max(Comparator.comparing(OtpItem::getCreatedAt))
              .map(OtpItem::toRecord);
        });
  }

  @Override
  public OptionalInt incrementAttempts(UserHandle userHandle, String otpId) {
    return DynamoDbSupport.wrap(
        "otp.incrementAttempts",
        () -> {
          // Atomic counter increment on the exact (pk, sk). No read, no scan. Two concurrent
          // verifies both succeed and each observes a distinct post-increment value via
          // UPDATED_NEW; the per-attempt cap check in OtpService remains the authority on lockout.
          String userB64 = Base64Url.encode(userHandle.value());
          try {
            UpdateItemResponse resp =
                client.updateItem(
                    UpdateItemRequest.builder()
                        .tableName(tableName)
                        .key(
                            Map.of(
                                "pk", AttributeValue.fromS("USER#" + userB64),
                                "sk", AttributeValue.fromS("OTP#" + otpId)))
                        .updateExpression("SET #a = if_not_exists(#a, :zero) + :one")
                        .conditionExpression("attribute_exists(pk)")
                        .expressionAttributeNames(Map.of("#a", "attempts"))
                        .expressionAttributeValues(
                            Map.of(
                                ":zero", AttributeValue.fromN("0"),
                                ":one", AttributeValue.fromN("1")))
                        .returnValues(ReturnValue.UPDATED_NEW)
                        .build());
            AttributeValue updated = resp.attributes().get("attempts");
            return updated == null
                ? OptionalInt.empty()
                : OptionalInt.of(Integer.parseInt(updated.n()));
          } catch (ConditionalCheckFailedException missing) {
            // OTP not found for this user — documented "no active record" branch.
            return OptionalInt.empty();
          }
        });
  }

  @Override
  public boolean consume(UserHandle userHandle, String otpId) {
    return DynamoDbSupport.wrap(
        "otp.consume",
        () -> {
          // Like backup-code consume, two concurrent verifies must NOT both succeed. The
          // conditional makes DynamoDB enforce single-use server-side. attribute_exists(pk)
          // prevents creating a phantom row if the (userHandle, otpId) pair doesn't exist.
          String userB64 = Base64Url.encode(userHandle.value());
          try {
            client.updateItem(
                UpdateItemRequest.builder()
                    .tableName(tableName)
                    .key(
                        Map.of(
                            "pk", AttributeValue.fromS("USER#" + userB64),
                            "sk", AttributeValue.fromS("OTP#" + otpId)))
                    .updateExpression("SET #c = :true")
                    .conditionExpression("attribute_exists(pk) AND #c = :false")
                    .expressionAttributeNames(Map.of("#c", "consumed"))
                    .expressionAttributeValues(
                        Map.of(
                            ":true", AttributeValue.fromBool(true),
                            ":false", AttributeValue.fromBool(false)))
                    .build());
            return true;
          } catch (ConditionalCheckFailedException ignored) {
            // Either the OTP doesn't exist for this user, or it was already consumed.
            return false;
          }
        });
  }

  @Override
  public int deleteByUserHandle(UserHandle userHandle) {
    return DynamoDbSupport.wrap(
        "otp.deleteByUserHandle",
        () -> {
          String userB64 = Base64Url.encode(userHandle.value());
          int[] removed = {0};
          table
              .query(
                  QueryConditional.sortBeginsWith(
                      Key.builder().partitionValue("USER#" + userB64).sortValue("OTP#").build()))
              .stream()
              .flatMap(page -> page.items().stream())
              .forEach(
                  item -> {
                    table.deleteItem(
                        Key.builder().partitionValue(item.getPk()).sortValue(item.getSk()).build());
                    removed[0]++;
                  });
          return removed[0];
        });
  }

  @Override
  public int countSince(UserHandle userHandle, String phoneE164, Instant since) {
    return DynamoDbSupport.wrap(
        "otp.countSince",
        () -> {
          String userB64 = Base64Url.encode(userHandle.value());
          return (int)
              table
                  .query(
                      QueryConditional.sortBeginsWith(
                          Key.builder()
                              .partitionValue("USER#" + userB64)
                              .sortValue("OTP#")
                              .build()))
                  .stream()
                  .flatMap(page -> page.items().stream())
                  .filter(i -> phoneE164.equals(i.getPhoneE164()))
                  .filter(i -> !Instant.parse(i.getCreatedAt()).isBefore(since))
                  .count();
        });
  }
}
