// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;

/**
 * Single-table mapping for stateful access-token rows (per ADR 0015). Each issued JTI lives at two
 * pk/sk addresses:
 *
 * <ul>
 *   <li>Primary: {@code pk = "AT#<jti>"}, {@code sk = "AT#<jti>"}; fast lookup by jti for {@code
 *       exists} and {@code delete}.
 *   <li>User-index: {@code pk = "USER#<userHandleB64u>"}, {@code sk = "AT#<jti>"}; fan-out path for
 *       {@code deleteAllForUser} alongside this user's other state.
 * </ul>
 *
 * <p>The {@code ttl} attribute is set to {@code expiresAt.epochSecond}, so DynamoDB's native TTL
 * sweep eventually removes expired rows. Synchronous pruning via {@code deleteExpiredBefore}
 * remains available for tests and operator-triggered cleanup that needs predictable timing.
 *
 * @since 1.1.0
 */
@DynamoDbBean
public class AccessTokenItem {

  private String pk;
  private String sk;
  private String jti;
  private String userHandleB64u;
  private String audience;
  private String deviceId;
  private String issuedAtIso;
  private String expiresAtIso;
  private Long ttl;

  public AccessTokenItem() {}

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

  public String getJti() {
    return jti;
  }

  public void setJti(String jti) {
    this.jti = jti;
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

  public Long getTtl() {
    return ttl;
  }

  public void setTtl(Long ttl) {
    this.ttl = ttl;
  }
}
