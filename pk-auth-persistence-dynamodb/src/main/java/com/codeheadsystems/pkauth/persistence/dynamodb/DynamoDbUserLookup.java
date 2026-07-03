// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spi.UserLookup;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbIndex;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Expression;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.TransactPutItemEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.TransactWriteItemsEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactionCanceledException;

/** {@link UserLookup} backed by the separate {@code PkAuthUsers} table. */
public final class DynamoDbUserLookup implements UserLookup {

  private final DynamoDbEnhancedClient enhanced;
  private final DynamoDbTable<UserItem> table;
  private final DynamoDbIndex<UserItem> byUsername;

  public DynamoDbUserLookup(DynamoDbEnhancedClient enhanced, PkAuthDynamoTables tables) {
    Objects.requireNonNull(enhanced, "enhanced");
    Objects.requireNonNull(tables, "tables");
    this.enhanced = enhanced;
    this.table = enhanced.table(tables.users(), TableSchema.fromBean(UserItem.class));
    this.byUsername = table.index(PkAuthDynamoTables.GSI1_USER_BY_USERNAME);
  }

  @Override
  public Optional<UserHandle> findHandleByUsername(String username) {
    return DynamoDbSupport.wrap(
        "users.findHandleByUsername",
        () ->
            lookupByUsername(username)
                .map(item -> UserHandle.of(Base64Url.decode(item.getUserHandle()))));
  }

  @Override
  public Optional<UserView> findViewByHandle(UserHandle handle) {
    return DynamoDbSupport.wrap(
        "users.findViewByHandle",
        () -> {
          String h = Base64Url.encode(handle.value());
          UserItem item =
              table.getItem(
                  Key.builder().partitionValue(DynamoKeys.USER + h).sortValue("META").build());
          return Optional.ofNullable(item).map(UserItem::toView);
        });
  }

  @Override
  public UserHandle getOrCreateHandle(String username) {
    return DynamoDbSupport.wrap(
        "users.getOrCreateHandle",
        () -> {
          Optional<UserItem> existing = lookupByUsername(username);
          if (existing.isPresent()) {
            return UserHandle.of(Base64Url.decode(existing.get().getUserHandle()));
          }
          UserHandle handle = UserHandle.random();
          // Write the user row AND a username-uniqueness marker atomically. The marker
          // (pk = USERNAME#<lowercased>) is the only guard that actually enforces one handle per
          // username: the user row's own pk is USER#<random handle>, so a condition on it never
          // collides on the username, and a GSI does not enforce uniqueness. Two concurrent
          // getOrCreateHandle calls for one username both mint a handle, but only one
          // TransactWriteItems can create the marker; the loser's transaction is cancelled.
          UserItem userItem = UserItem.build(handle, username, username);
          UserItem marker = UserItem.usernameMarker(handle, username);
          Expression notExists =
              Expression.builder().expression("attribute_not_exists(pk)").build();
          try {
            enhanced.transactWriteItems(
                TransactWriteItemsEnhancedRequest.builder()
                    .addPutItem(
                        table,
                        TransactPutItemEnhancedRequest.builder(UserItem.class)
                            .item(userItem)
                            .conditionExpression(notExists)
                            .build())
                    .addPutItem(
                        table,
                        TransactPutItemEnhancedRequest.builder(UserItem.class)
                            .item(marker)
                            .conditionExpression(notExists)
                            .build())
                    .build());
            return handle;
          } catch (TransactionCanceledException race) {
            // The username was claimed by a concurrent (or prior) creator. Recover the winner's
            // handle from the marker with a STRONGLY-consistent read: the winning transaction wrote
            // the marker atomically, so it is visible immediately, whereas the username GSI is only
            // eventually consistent and may not reflect the winner's row yet. If no marker exists,
            // the cancellation was transient (throughput / conflict), not a uniqueness clash, so
            // rethrow — it surfaces as a 503 rather than returning an unpersisted handle.
            UserItem winner =
                table.getItem(
                    GetItemEnhancedRequest.builder()
                        .key(
                            Key.builder()
                                .partitionValue(
                                    DynamoKeys.USERNAME + username.toLowerCase(Locale.ROOT))
                                .sortValue("META")
                                .build())
                        .consistentRead(true)
                        .build());
            if (winner != null) {
              return UserHandle.of(Base64Url.decode(winner.getUserHandle()));
            }
            throw race;
          }
        });
  }

  /** Pre-registers a user (test fixture support). */
  public UserHandle register(String username, String displayName) {
    UserHandle handle = UserHandle.random();
    DynamoDbSupport.wrap(
        "users.register",
        () -> {
          table.putItem(UserItem.build(handle, username, displayName));
          return null;
        });
    return handle;
  }

  private Optional<UserItem> lookupByUsername(String username) {
    String key = DynamoKeys.USERNAME + username.toLowerCase(Locale.ROOT);
    return byUsername
        .query(
            QueryConditional.keyEqualTo(
                Key.builder().partitionValue(key).sortValue("META").build()))
        .stream()
        .flatMap(page -> page.items().stream())
        .findFirst();
  }
}
