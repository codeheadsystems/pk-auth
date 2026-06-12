// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository.StoredBackupCode;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;

/** Backup-code row in the {@code PkAuthCore} single-table (ADR 0008). */
@DynamoDbBean
public final class BackupCodeItem {

  private String pk;
  private String sk;
  private String entityType;
  private String codeId;
  private String userHandle;
  private String hashedCode;
  private boolean consumed;
  private String consumedAt;
  private String createdAt;

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

  public String getEntityType() {
    return entityType;
  }

  public void setEntityType(String entityType) {
    this.entityType = entityType;
  }

  public String getCodeId() {
    return codeId;
  }

  public void setCodeId(String codeId) {
    this.codeId = codeId;
  }

  public String getUserHandle() {
    return userHandle;
  }

  public void setUserHandle(String userHandle) {
    this.userHandle = userHandle;
  }

  public String getHashedCode() {
    return hashedCode;
  }

  public void setHashedCode(String hashedCode) {
    this.hashedCode = hashedCode;
  }

  public boolean isConsumed() {
    return consumed;
  }

  public void setConsumed(boolean consumed) {
    this.consumed = consumed;
  }

  public String getConsumedAt() {
    return consumedAt;
  }

  public void setConsumedAt(String consumedAt) {
    this.consumedAt = consumedAt;
  }

  public String getCreatedAt() {
    return createdAt;
  }

  public void setCreatedAt(String createdAt) {
    this.createdAt = createdAt;
  }

  /** Builds an item from a {@link StoredBackupCode}. */
  public static BackupCodeItem fromRecord(StoredBackupCode c) {
    String userB64 = Base64Url.encode(c.userHandle().value());
    BackupCodeItem item = new BackupCodeItem();
    item.setPk(DynamoKeys.USER + userB64);
    item.setSk(DynamoKeys.BACKUP + c.codeId());
    item.setEntityType("BackupCode");
    item.setCodeId(c.codeId());
    item.setUserHandle(userB64);
    item.setHashedCode(c.hashedCode());
    item.setConsumed(c.consumed());
    item.setConsumedAt(DynamoDbSupport.encodeInstantOrNull(c.consumedAt()));
    item.setCreatedAt(DynamoDbSupport.encodeInstant(c.createdAt()));
    return item;
  }

  /** Materializes the row as a {@link StoredBackupCode}. */
  public StoredBackupCode toRecord() {
    return new StoredBackupCode(
        codeId,
        UserHandle.of(Base64Url.decode(userHandle)),
        hashedCode,
        consumed,
        DynamoDbSupport.parseInstant(createdAt),
        DynamoDbSupport.parseInstantOrNull(consumedAt));
  }
}
