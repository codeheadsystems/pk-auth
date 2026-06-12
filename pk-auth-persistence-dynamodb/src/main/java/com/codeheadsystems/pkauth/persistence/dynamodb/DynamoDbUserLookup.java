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
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;

/** {@link UserLookup} backed by the separate {@code PkAuthUsers} table. */
public final class DynamoDbUserLookup implements UserLookup {

  private final DynamoDbTable<UserItem> table;
  private final DynamoDbIndex<UserItem> byUsername;

  public DynamoDbUserLookup(DynamoDbEnhancedClient enhanced, PkAuthDynamoTables tables) {
    Objects.requireNonNull(enhanced, "enhanced");
    Objects.requireNonNull(tables, "tables");
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
              table.getItem(Key.builder().partitionValue("USER#" + h).sortValue("META").build());
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
          UserItem item = UserItem.build(handle, username, username);
          try {
            table.putItem(
                r ->
                    r.item(item)
                        .conditionExpression(
                            Expression.builder().expression("attribute_not_exists(pk)").build()));
            return handle;
          } catch (ConditionalCheckFailedException race) {
            return lookupByUsername(username)
                .map(u -> UserHandle.of(Base64Url.decode(u.getUserHandle())))
                .orElse(handle);
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
    String key = "USERNAME#" + username.toLowerCase(Locale.ROOT);
    return byUsername
        .query(
            QueryConditional.keyEqualTo(
                Key.builder().partitionValue(key).sortValue("META").build()))
        .stream()
        .flatMap(page -> page.items().stream())
        .findFirst();
  }
}
