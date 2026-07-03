// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spi.UserLookup.UserView;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondarySortKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;

/** Row in the separate {@code PkAuthUsers} table — host-app data per brief §6.7. */
@DynamoDbBean
public final class UserItem {

  private String pk;
  private String sk;
  private String userHandle;
  private String username;
  private String displayName;
  private boolean emailVerified;
  private boolean phoneVerified;
  private String gsi1pk;
  private String gsi1sk;

  @DynamoDbPartitionKey
  public String getPk() {
    return pk;
  }

  public void setPk(String pk) {
    this.pk = pk;
  }

  @DynamoDbSortKey
  public String getSk() {
    return sk;
  }

  public void setSk(String sk) {
    this.sk = sk;
  }

  public String getUserHandle() {
    return userHandle;
  }

  public void setUserHandle(String userHandle) {
    this.userHandle = userHandle;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getDisplayName() {
    return displayName;
  }

  public void setDisplayName(String displayName) {
    this.displayName = displayName;
  }

  public boolean isEmailVerified() {
    return emailVerified;
  }

  public void setEmailVerified(boolean emailVerified) {
    this.emailVerified = emailVerified;
  }

  public boolean isPhoneVerified() {
    return phoneVerified;
  }

  public void setPhoneVerified(boolean phoneVerified) {
    this.phoneVerified = phoneVerified;
  }

  @DynamoDbSecondaryPartitionKey(indexNames = PkAuthDynamoTables.GSI1_USER_BY_USERNAME)
  public String getGsi1pk() {
    return gsi1pk;
  }

  public void setGsi1pk(String gsi1pk) {
    this.gsi1pk = gsi1pk;
  }

  @DynamoDbSecondarySortKey(indexNames = PkAuthDynamoTables.GSI1_USER_BY_USERNAME)
  public String getGsi1sk() {
    return gsi1sk;
  }

  public void setGsi1sk(String gsi1sk) {
    this.gsi1sk = gsi1sk;
  }

  /** Builds a row from a user handle + username + display name. */
  public static UserItem build(UserHandle handle, String username, String displayName) {
    String h = Base64Url.encode(handle.value());
    UserItem item = new UserItem();
    item.setPk(DynamoKeys.USER + h);
    item.setSk("META");
    item.setUserHandle(h);
    item.setUsername(username);
    item.setDisplayName(displayName);
    item.setEmailVerified(false);
    item.setPhoneVerified(false);
    item.setGsi1pk(DynamoKeys.USERNAME + username.toLowerCase(java.util.Locale.ROOT));
    item.setGsi1sk("META");
    return item;
  }

  /**
   * Builds the username-uniqueness marker row: {@code pk = USERNAME#<lowercased>}, {@code sk =
   * META}. A conditional put of this item ({@code attribute_not_exists(pk)}) is what actually
   * enforces one handle per username — a GSI cannot, because GSIs do not enforce uniqueness.
   * Deliberately leaves {@code gsi1pk} unset so the sparse username GSI does not index it (only the
   * real {@link DynamoKeys#USER} row is indexed and returned by lookups); it carries {@code
   * userHandle} so a racing loser can recover the winner's handle with a strongly-consistent read.
   */
  static UserItem usernameMarker(UserHandle handle, String username) {
    UserItem item = new UserItem();
    item.setPk(DynamoKeys.USERNAME + username.toLowerCase(java.util.Locale.ROOT));
    item.setSk("META");
    item.setUserHandle(Base64Url.encode(handle.value()));
    item.setUsername(username);
    return item;
  }

  /** Renders the row as a public {@link UserView}. */
  public UserView toView() {
    return new UserView(
        UserHandle.of(Base64Url.decode(userHandle)),
        username,
        displayName,
        emailVerified,
        phoneVerified);
  }
}
