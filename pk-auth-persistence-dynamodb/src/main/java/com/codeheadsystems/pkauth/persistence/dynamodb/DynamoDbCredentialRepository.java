// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.DuplicateCredentialException;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbIndex;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.UpdateItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;

/** {@link CredentialRepository} backed by the {@code PkAuthCore} single-table. */
public final class DynamoDbCredentialRepository implements CredentialRepository {

  /** Maximum number of optimistic-lock retries for field-level update operations. */
  private static final int MAX_RETRIES = 3;

  private final DynamoDbTable<CredentialItem> table;
  private final DynamoDbIndex<CredentialItem> credentialByIdIndex;

  public DynamoDbCredentialRepository(DynamoDbEnhancedClient enhanced, PkAuthDynamoTables tables) {
    Objects.requireNonNull(enhanced, "enhanced");
    Objects.requireNonNull(tables, "tables");
    this.table = enhanced.table(tables.core(), TableSchema.fromBean(CredentialItem.class));
    this.credentialByIdIndex = table.index(PkAuthDynamoTables.GSI1_CREDENTIAL_BY_ID);
  }

  @Override
  public void save(CredentialRecord record) {
    DynamoDbSupport.wrap(
        "credentials.save",
        () -> {
          try {
            table.putItem(
                r ->
                    r.item(CredentialItem.fromRecord(record))
                        .conditionExpression(
                            software.amazon.awssdk.enhanced.dynamodb.Expression.builder()
                                .expression("attribute_not_exists(pk)")
                                .build()));
          } catch (ConditionalCheckFailedException e) {
            throw new DuplicateCredentialException(
                "Duplicate credential id; refusing to overwrite an existing credential", e);
          }
          return null;
        });
  }

  @Override
  public Optional<CredentialRecord> findByCredentialId(CredentialId credentialId) {
    return DynamoDbSupport.wrap(
        "credentials.findByCredentialId",
        () -> {
          String credIdB64 = credentialId.b64url();
          return credentialByIdIndex
              .query(
                  QueryConditional.keyEqualTo(
                      Key.builder()
                          .partitionValue(DynamoKeys.CRED + credIdB64)
                          .sortValue("META")
                          .build()))
              .stream()
              .flatMap(page -> page.items().stream())
              .findFirst()
              .map(CredentialItem::toRecord);
        });
  }

  @Override
  public List<CredentialRecord> findByUserHandle(UserHandle userHandle) {
    return DynamoDbSupport.wrap(
        "credentials.findByUserHandle",
        () -> {
          String userB64 = Base64Url.encode(userHandle.value());
          return table
              .query(
                  QueryConditional.sortBeginsWith(
                      Key.builder()
                          .partitionValue(DynamoKeys.USER + userB64)
                          .sortValue(DynamoKeys.CRED)
                          .build()))
              .stream()
              .flatMap(page -> page.items().stream())
              .map(CredentialItem::toRecord)
              .toList();
        });
  }

  @Override
  public void updateSignCount(CredentialId credentialId, long newCount, Instant lastUsedAt) {
    DynamoDbSupport.wrap(
        "credentials.updateSignCount",
        () -> {
          // Retry loop: @DynamoDbVersionAttribute provides optimistic concurrency — if a concurrent
          // writer (e.g. updateLabel) changes the item between our read and write, the enhanced
          // client throws ConditionalCheckFailedException. We re-fetch and re-apply up to
          // MAX_RETRIES times.
          for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
            Optional<CredentialItem> existing = lookupItem(credentialId);
            if (existing.isEmpty()) {
              return null;
            }
            CredentialItem item = existing.get();
            item.setSignCount(newCount);
            item.setLastUsedAt(DynamoDbSupport.encodeInstant(lastUsedAt));
            // Guard against the lost-update race: two concurrent assertions (e.g. a clone vs. the
            // real authenticator) would otherwise overwrite a higher stored counter with a lower
            // one, silently defeating clone detection. The conditional rejects the write unless
            // the in-table value is still strictly less than the value we're trying to store. The
            // version check from @DynamoDbVersionAttribute is automatically ANDed in by the
            // enhanced client.
            try {
              table.updateItem(
                  UpdateItemEnhancedRequest.builder(CredentialItem.class)
                      .item(item)
                      .conditionExpression(
                          software.amazon.awssdk.enhanced.dynamodb.Expression.builder()
                              .expression("signCount < :newSignCount")
                              .putExpressionValue(
                                  ":newSignCount",
                                  software.amazon.awssdk.services.dynamodb.model.AttributeValue
                                      .fromN(Long.toString(newCount)))
                              .build())
                      .build());
              return null; // success
            } catch (ConditionalCheckFailedException e) {
              // Either the version changed (concurrent update — retry) or another writer already
              // advanced signCount to >= newCount (clone-detection defence — give up immediately).
              Optional<CredentialItem> current = lookupItem(credentialId);
              if (current.isPresent() && current.get().getSignCount() >= newCount) {
                // A concurrent write already advanced the counter; nothing to do.
                return null;
              }
              // Version conflict from a concurrent field update — loop and retry.
            }
          }
          return null;
        });
  }

  @Override
  public void updateLabel(UserHandle userHandle, CredentialId credentialId, String label) {
    DynamoDbSupport.wrap(
        "credentials.updateLabel",
        () -> {
          // Retry loop: guards against concurrent field updates clobbering each other via the
          // @DynamoDbVersionAttribute optimistic-lock on CredentialItem.
          for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
            Optional<CredentialItem> existing = lookupItem(credentialId);
            if (existing.isEmpty()) {
              return null;
            }
            CredentialItem item = existing.get();
            // Defense-in-depth: refuse to mutate a credential whose owner doesn't match the
            // caller. Silent no-op so behaviour mirrors the no-op of "row not found" (callers
            // already verified existence via findByCredentialId at the service layer).
            if (!Base64Url.encode(userHandle.value()).equals(item.getUserHandle())) {
              return null;
            }
            item.setLabel(label);
            try {
              table.updateItem(
                  UpdateItemEnhancedRequest.builder(CredentialItem.class).item(item).build());
              return null; // success
            } catch (ConditionalCheckFailedException ignored) {
              // Version conflict from a concurrent update — re-fetch and retry.
            }
          }
          return null;
        });
  }

  @Override
  public void delete(UserHandle userHandle, CredentialId credentialId) {
    DynamoDbSupport.wrap(
        "credentials.delete",
        () -> {
          lookupItem(credentialId)
              .ifPresent(
                  item -> {
                    if (!Base64Url.encode(userHandle.value()).equals(item.getUserHandle())) {
                      return; // defense-in-depth ownership mismatch
                    }
                    table.deleteItem(
                        Key.builder().partitionValue(item.getPk()).sortValue(item.getSk()).build());
                  });
          return null;
        });
  }

  @Override
  public int deleteByUserHandle(UserHandle userHandle) {
    return DynamoDbSupport.wrap(
        "credentials.deleteByUserHandle",
        () -> {
          String userB64 = Base64Url.encode(userHandle.value());
          int[] removed = {0};
          table
              .query(
                  QueryConditional.sortBeginsWith(
                      Key.builder()
                          .partitionValue(DynamoKeys.USER + userB64)
                          .sortValue(DynamoKeys.CRED)
                          .build()))
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

  private Optional<CredentialItem> lookupItem(CredentialId credentialId) {
    String credIdB64 = credentialId.b64url();
    return credentialByIdIndex
        .query(
            QueryConditional.keyEqualTo(
                Key.builder()
                    .partitionValue(DynamoKeys.CRED + credIdB64)
                    .sortValue("META")
                    .build()))
        .stream()
        .flatMap(page -> page.items().stream())
        .findFirst();
  }

  /** Diagnostic helper to expose the table name for inspection in tests. */
  Map<String, AttributeValue> asRawKey(String pk, String sk) {
    Map<String, AttributeValue> key = new HashMap<>();
    key.put("pk", AttributeValue.fromS(pk));
    key.put("sk", AttributeValue.fromS(sk));
    return key;
  }
}
