// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;

/**
 * Single-table mapping for refresh-token rows on {@code PkAuthCore}. Three logical item shapes
 * share this bean, distinguished by the {@code pk}/{@code sk} pattern:
 *
 * <ul>
 *   <li>Primary: {@code pk = "RT#<refreshId>"}, {@code sk = "RT#<refreshId>"} — fast lookup by
 *       refreshId. The load-bearing row for rotation.
 *   <li>User-index: {@code pk = "USER#<userHandleB64u>"}, {@code sk = "RT#<refreshId>"} — listing
 *       and {@code revokeAllForUser} fan-out alongside this user's other state.
 *   <li>Family-index: {@code pk = "RTF#<familyId>"}, {@code sk = "RT#<refreshId>"} — fast scorch of
 *       every member of a family.
 * </ul>
 *
 * <p>Two epoch-second attributes drive the lifecycle. {@code expiresAtEpoch} is the token's hard
 * expiry and is what the {@code rotateAtomically} freshness condition compares against — a numeric
 * compare avoids the variable-precision pitfall of comparing {@code Instant.toString()} ISO
 * strings. {@code ttl} is {@code expiresAt + cleanupRetention}.epochSecond and is the attribute
 * DynamoDB's native TTL prunes on, so used / revoked / expired rows survive the forensic-retention
 * window before being swept. Synchronous cleanup via {@code deleteExpiredBefore} stays available
 * for tests and operator-driven retention.
 *
 * @since 1.1.0
 */
@DynamoDbBean
public class RefreshTokenItem {

  private String pk;
  private String sk;
  private String refreshId;
  private String tokenHashB64u;
  private String userHandleB64u;
  private String audience;
  private String deviceId;
  private String familyId;
  private String parentRefreshId;
  private String issuedAtIso;
  private String expiresAtIso;
  private String usedAtIso;
  private String revokedAtIso;
  private String revokedReason;
  private String amr;
  private Long expiresAtEpoch;
  private Long ttl;

  public RefreshTokenItem() {}

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

  public String getRefreshId() {
    return refreshId;
  }

  public void setRefreshId(String refreshId) {
    this.refreshId = refreshId;
  }

  public String getTokenHashB64u() {
    return tokenHashB64u;
  }

  public void setTokenHashB64u(String tokenHashB64u) {
    this.tokenHashB64u = tokenHashB64u;
  }

  public String getUserHandleB64u() {
    return userHandleB64u;
  }

  public void setUserHandleB64u(String userHandleB64u) {
    this.userHandleB64u = userHandleB64u;
  }

  public String getAudience() {
    return audience;
  }

  public void setAudience(String audience) {
    this.audience = audience;
  }

  public String getDeviceId() {
    return deviceId;
  }

  public void setDeviceId(String deviceId) {
    this.deviceId = deviceId;
  }

  public String getFamilyId() {
    return familyId;
  }

  public void setFamilyId(String familyId) {
    this.familyId = familyId;
  }

  public String getParentRefreshId() {
    return parentRefreshId;
  }

  public void setParentRefreshId(String parentRefreshId) {
    this.parentRefreshId = parentRefreshId;
  }

  public String getIssuedAtIso() {
    return issuedAtIso;
  }

  public void setIssuedAtIso(String issuedAtIso) {
    this.issuedAtIso = issuedAtIso;
  }

  public String getExpiresAtIso() {
    return expiresAtIso;
  }

  public void setExpiresAtIso(String expiresAtIso) {
    this.expiresAtIso = expiresAtIso;
  }

  public String getUsedAtIso() {
    return usedAtIso;
  }

  public void setUsedAtIso(String usedAtIso) {
    this.usedAtIso = usedAtIso;
  }

  public String getRevokedAtIso() {
    return revokedAtIso;
  }

  public void setRevokedAtIso(String revokedAtIso) {
    this.revokedAtIso = revokedAtIso;
  }

  public String getRevokedReason() {
    return revokedReason;
  }

  public void setRevokedReason(String revokedReason) {
    this.revokedReason = revokedReason;
  }

  /** RFC 8176 {@code amr} method references, stored comma-separated (e.g. "pkauth,webauthn"). */
  public String getAmr() {
    return amr;
  }

  public void setAmr(String amr) {
    this.amr = amr;
  }

  /**
   * Hard expiry as an epoch second; drives the numeric freshness check in {@code rotateAtomically}.
   */
  public Long getExpiresAtEpoch() {
    return expiresAtEpoch;
  }

  public void setExpiresAtEpoch(Long expiresAtEpoch) {
    this.expiresAtEpoch = expiresAtEpoch;
  }

  public Long getTtl() {
    return ttl;
  }

  public void setTtl(Long ttl) {
    this.ttl = ttl;
  }
}
