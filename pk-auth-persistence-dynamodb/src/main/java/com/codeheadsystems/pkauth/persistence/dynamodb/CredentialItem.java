// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.Transport;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.json.Base64Url;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import software.amazon.awssdk.enhanced.dynamodb.extensions.annotations.DynamoDbVersionAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondarySortKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;

/**
 * DynamoDB row backing a registered credential, per ADR 0008. Binary fields are stored as base64url
 * strings (brief §6.7 wire-format choice).
 */
@DynamoDbBean
public final class CredentialItem {

  private String pk;
  private String sk;
  private String entityType;
  private String gsi1pk;
  private String gsi1sk;
  private String credentialId;
  private String userHandle;
  private String publicKeyCose;
  private long signCount;
  private String label;
  private String aaguid;
  private Set<String> transports;
  private boolean backupEligible;
  private boolean backupState;
  private String createdAt;
  private String lastUsedAt;
  private Long version;

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

  @DynamoDbAttribute("entityType")
  public String getEntityType() {
    return entityType;
  }

  public void setEntityType(String entityType) {
    this.entityType = entityType;
  }

  @DynamoDbSecondaryPartitionKey(indexNames = PkAuthDynamoTables.GSI1_CREDENTIAL_BY_ID)
  public String getGsi1pk() {
    return gsi1pk;
  }

  public void setGsi1pk(String gsi1pk) {
    this.gsi1pk = gsi1pk;
  }

  @DynamoDbSecondarySortKey(indexNames = PkAuthDynamoTables.GSI1_CREDENTIAL_BY_ID)
  public String getGsi1sk() {
    return gsi1sk;
  }

  public void setGsi1sk(String gsi1sk) {
    this.gsi1sk = gsi1sk;
  }

  public String getCredentialId() {
    return credentialId;
  }

  public void setCredentialId(String credentialId) {
    this.credentialId = credentialId;
  }

  public String getUserHandle() {
    return userHandle;
  }

  public void setUserHandle(String userHandle) {
    this.userHandle = userHandle;
  }

  public String getPublicKeyCose() {
    return publicKeyCose;
  }

  public void setPublicKeyCose(String publicKeyCose) {
    this.publicKeyCose = publicKeyCose;
  }

  public long getSignCount() {
    return signCount;
  }

  public void setSignCount(long signCount) {
    this.signCount = signCount;
  }

  public String getLabel() {
    return label;
  }

  public void setLabel(String label) {
    this.label = label;
  }

  public String getAaguid() {
    return aaguid;
  }

  public void setAaguid(String aaguid) {
    this.aaguid = aaguid;
  }

  public Set<String> getTransports() {
    return transports;
  }

  public void setTransports(Set<String> transports) {
    this.transports = transports;
  }

  public boolean isBackupEligible() {
    return backupEligible;
  }

  public void setBackupEligible(boolean backupEligible) {
    this.backupEligible = backupEligible;
  }

  public boolean isBackupState() {
    return backupState;
  }

  public void setBackupState(boolean backupState) {
    this.backupState = backupState;
  }

  public String getCreatedAt() {
    return createdAt;
  }

  public void setCreatedAt(String createdAt) {
    this.createdAt = createdAt;
  }

  public String getLastUsedAt() {
    return lastUsedAt;
  }

  public void setLastUsedAt(String lastUsedAt) {
    this.lastUsedAt = lastUsedAt;
  }

  /**
   * Optimistic-concurrency version managed automatically by the DynamoDB Enhanced Client. The
   * enhanced client increments this on every put/update and adds a condition expression that
   * rejects the write if the stored version has changed, preventing lost-update races between
   * concurrent field mutators (e.g. {@code updateLabel} vs {@code updateSignCount}).
   */
  @DynamoDbVersionAttribute
  public Long getVersion() {
    return version;
  }

  public void setVersion(Long version) {
    this.version = version;
  }

  /** Translates one of our {@link CredentialRecord} values into a DynamoDB item. */
  public static CredentialItem fromRecord(CredentialRecord r) {
    String credIdB64 = r.credentialId().b64url();
    String userB64 = Base64Url.encode(r.userHandle().value());
    CredentialItem item = new CredentialItem();
    item.setPk(DynamoKeys.USER + userB64);
    item.setSk(DynamoKeys.CRED + credIdB64);
    item.setEntityType("Credential");
    item.setGsi1pk(DynamoKeys.CRED + credIdB64);
    item.setGsi1sk("META");
    item.setCredentialId(credIdB64);
    item.setUserHandle(userB64);
    item.setPublicKeyCose(Base64Url.encode(r.publicKeyCose()));
    item.setSignCount(r.signCount());
    item.setLabel(r.label());
    item.setAaguid(r.aaguid() == null ? null : r.aaguid().toString());
    if (r.transports().isEmpty()) {
      item.setTransports(null);
    } else {
      Set<String> wire = new LinkedHashSet<>();
      for (Transport t : r.transports()) {
        wire.add(t.wireName());
      }
      item.setTransports(wire);
    }
    item.setBackupEligible(r.backupEligible());
    item.setBackupState(r.backupState());
    item.setCreatedAt(DynamoDbSupport.encodeInstant(r.createdAt()));
    item.setLastUsedAt(DynamoDbSupport.encodeInstantOrNull(r.lastUsedAt()));
    return item;
  }

  /** Translates a DynamoDB item back into a {@link CredentialRecord}. */
  public CredentialRecord toRecord() {
    Set<Transport> tx = EnumSet.noneOf(Transport.class);
    if (transports != null) {
      for (String t : transports) {
        Transport.fromWire(t).ifPresent(tx::add);
      }
    }
    return new CredentialRecord(
        CredentialId.fromB64Url(credentialId),
        UserHandle.of(Base64Url.decode(userHandle)),
        Base64Url.decode(publicKeyCose),
        signCount,
        label,
        aaguid == null ? null : UUID.fromString(aaguid),
        tx,
        backupEligible,
        backupState,
        DynamoDbSupport.parseInstant(createdAt),
        DynamoDbSupport.parseInstantOrNull(lastUsedAt));
  }
}
