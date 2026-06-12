// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spi.OtpRepository.StoredOtp;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;

/** OTP row in the {@code PkAuthCore} single-table (ADR 0008). */
@DynamoDbBean
public final class OtpItem {

  private String pk;
  private String sk;
  private String entityType;
  private Long ttl;
  private String otpId;
  private String userHandle;
  private String phoneE164;
  private String hashedCode;
  private int attempts;
  private int maxAttempts;
  private boolean consumed;
  private String createdAt;
  private String expiresAt;

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

  public Long getTtl() {
    return ttl;
  }

  public void setTtl(Long ttl) {
    this.ttl = ttl;
  }

  public String getOtpId() {
    return otpId;
  }

  public void setOtpId(String otpId) {
    this.otpId = otpId;
  }

  public String getUserHandle() {
    return userHandle;
  }

  public void setUserHandle(String userHandle) {
    this.userHandle = userHandle;
  }

  public String getPhoneE164() {
    return phoneE164;
  }

  public void setPhoneE164(String phoneE164) {
    this.phoneE164 = phoneE164;
  }

  public String getHashedCode() {
    return hashedCode;
  }

  public void setHashedCode(String hashedCode) {
    this.hashedCode = hashedCode;
  }

  public int getAttempts() {
    return attempts;
  }

  public void setAttempts(int attempts) {
    this.attempts = attempts;
  }

  public int getMaxAttempts() {
    return maxAttempts;
  }

  public void setMaxAttempts(int maxAttempts) {
    this.maxAttempts = maxAttempts;
  }

  public boolean isConsumed() {
    return consumed;
  }

  public void setConsumed(boolean consumed) {
    this.consumed = consumed;
  }

  public String getCreatedAt() {
    return createdAt;
  }

  public void setCreatedAt(String createdAt) {
    this.createdAt = createdAt;
  }

  public String getExpiresAt() {
    return expiresAt;
  }

  public void setExpiresAt(String expiresAt) {
    this.expiresAt = expiresAt;
  }

  /** Builds an item from a {@link StoredOtp}. */
  public static OtpItem fromRecord(StoredOtp o) {
    String userB64 = Base64Url.encode(o.userHandle().value());
    OtpItem item = new OtpItem();
    item.setPk(DynamoKeys.USER + userB64);
    item.setSk(DynamoKeys.OTP + o.otpId());
    item.setEntityType("OtpCode");
    item.setTtl(o.expiresAt().getEpochSecond());
    item.setOtpId(o.otpId());
    item.setUserHandle(userB64);
    item.setPhoneE164(o.phoneE164());
    item.setHashedCode(o.hashedCode());
    item.setAttempts(o.attempts());
    item.setMaxAttempts(o.maxAttempts());
    item.setConsumed(o.consumed());
    item.setCreatedAt(DynamoDbSupport.encodeInstant(o.createdAt()));
    item.setExpiresAt(DynamoDbSupport.encodeInstant(o.expiresAt()));
    return item;
  }

  /** Materializes the row as a {@link StoredOtp}. */
  public StoredOtp toRecord() {
    return new StoredOtp(
        otpId,
        UserHandle.of(Base64Url.decode(userHandle)),
        phoneE164,
        hashedCode,
        attempts,
        maxAttempts,
        consumed,
        DynamoDbSupport.parseInstant(createdAt),
        DynamoDbSupport.parseInstant(expiresAt));
  }
}
