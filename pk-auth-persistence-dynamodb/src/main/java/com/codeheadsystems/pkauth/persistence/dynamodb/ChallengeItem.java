// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.api.UserVerificationRequirement;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spi.ChallengeRecord;
import java.time.Instant;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;

/** DynamoDB row backing an in-flight WebAuthn challenge. */
@DynamoDbBean
public final class ChallengeItem {

  private String pk;
  private String sk;
  private String entityType;
  private Long ttl;
  private String challenge;
  private String purpose;
  private String userHandle;
  private String userVerification;
  private Long expiresAt;

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

  public String getChallenge() {
    return challenge;
  }

  public void setChallenge(String challenge) {
    this.challenge = challenge;
  }

  public String getPurpose() {
    return purpose;
  }

  public void setPurpose(String purpose) {
    this.purpose = purpose;
  }

  public String getUserHandle() {
    return userHandle;
  }

  public void setUserHandle(String userHandle) {
    this.userHandle = userHandle;
  }

  public String getUserVerification() {
    return userVerification;
  }

  public void setUserVerification(String userVerification) {
    this.userVerification = userVerification;
  }

  public Long getExpiresAt() {
    return expiresAt;
  }

  public void setExpiresAt(Long expiresAt) {
    this.expiresAt = expiresAt;
  }

  /** Constructs a DynamoDB row from a ChallengeId + record + computed expiry epoch second. */
  public static ChallengeItem build(ChallengeId id, ChallengeRecord record) {
    ChallengeItem item = new ChallengeItem();
    item.setPk(DynamoKeys.CHAL + id.value());
    item.setSk("META");
    item.setEntityType("Challenge");
    item.setTtl(record.expiresAt().getEpochSecond());
    item.setChallenge(Base64Url.encode(record.challenge()));
    item.setPurpose(record.purpose().name());
    item.setUserHandle(
        record.userHandle() == null ? null : Base64Url.encode(record.userHandle().value()));
    item.setUserVerification(
        record.userVerification() == null ? null : record.userVerification().name());
    item.setExpiresAt(record.expiresAt().toEpochMilli());
    return item;
  }

  /** Materializes the stored row back into a {@link ChallengeRecord}. */
  public ChallengeRecord toRecord() {
    return new ChallengeRecord(
        Base64Url.decode(challenge),
        ChallengeRecord.Purpose.valueOf(purpose),
        userHandle == null ? null : UserHandle.of(Base64Url.decode(userHandle)),
        userVerification == null ? null : UserVerificationRequirement.valueOf(userVerification),
        Instant.ofEpochMilli(expiresAt));
  }
}
