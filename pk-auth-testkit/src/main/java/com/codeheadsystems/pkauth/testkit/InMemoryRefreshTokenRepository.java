// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.refresh.RefreshTokenRecord;
import com.codeheadsystems.pkauth.refresh.RevokeReason;
import com.codeheadsystems.pkauth.refresh.spi.RefreshTokenRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link RefreshTokenRepository}. Backed by a {@link ConcurrentHashMap}; the load-bearing
 * {@link #rotateAtomically} primitive speculatively inserts the successor, then serializes the
 * parent's mark-used via {@link java.util.concurrent.ConcurrentMap#compute}, rolling the successor
 * back if the parent was not fresh. Exactly one of N concurrent rotators of the same parent wins.
 *
 * @since 1.1.0
 */
public final class InMemoryRefreshTokenRepository implements RefreshTokenRepository {

  private final Map<String, RefreshTokenRecord> byRefreshId = new ConcurrentHashMap<>();

  public InMemoryRefreshTokenRepository() {}

  @Override
  public void create(RefreshTokenRecord record) {
    if (byRefreshId.putIfAbsent(record.refreshId(), record) != null) {
      throw new IllegalStateException("duplicate refreshId: " + record.refreshId());
    }
  }

  @Override
  public Optional<RefreshTokenRecord> findByRefreshId(String refreshId) {
    return Optional.ofNullable(byRefreshId.get(refreshId));
  }

  @Override
  public boolean rotateAtomically(
      String parentRefreshId, Instant now, RefreshTokenRecord successor) {
    // Insert the successor under its own key FIRST, then serialize the parent's mark-used via
    // compute(). The successor write MUST happen outside compute(): ConcurrentHashMap.compute
    // forbids updating any other mapping of the same map from within the remapping function (risk
    // of lockup / undefined behavior), so the prior nested putIfAbsent was illegal. A successor id
    // collision aborts without disturbing the existing entry; if the parent turns out non-fresh
    // (already used/revoked/expired, or missing) we roll our speculative successor back out so a
    // lost rotation leaves no orphan. compute() on the parent still serializes concurrent rotators,
    // so exactly one flips used_at and returns true.
    if (byRefreshId.putIfAbsent(successor.refreshId(), successor) != null) {
      return false; // duplicate successor id → abort, never half-commit
    }
    boolean[] rotated = {false};
    byRefreshId.compute(
        parentRefreshId,
        (k, existing) -> {
          if (existing == null) {
            return null; // missing parent → no rotation
          }
          if (existing.usedAt().isPresent()
              || existing.revokedAt().isPresent()
              || !existing.expiresAt().isAfter(now)) {
            return existing; // not fresh → no rotation
          }
          rotated[0] = true;
          return markUsed(existing, now);
        });
    if (!rotated[0]) {
      // Roll back the speculative insert; remove(key, value) only deletes our own successor.
      byRefreshId.remove(successor.refreshId(), successor);
    }
    return rotated[0];
  }

  @Override
  public int revokeFamily(String familyId, Instant now, RevokeReason reason) {
    int[] affected = {0};
    byRefreshId.replaceAll(
        (k, v) -> {
          if (v.familyId().equals(familyId) && v.revokedAt().isEmpty()) {
            affected[0]++;
            return markRevoked(v, now, reason);
          }
          return v;
        });
    return affected[0];
  }

  @Override
  public int revokeAllForUser(UserHandle userHandle, Instant now, RevokeReason reason) {
    int[] affected = {0};
    byRefreshId.replaceAll(
        (k, v) -> {
          if (v.userHandle().equals(userHandle) && v.revokedAt().isEmpty()) {
            affected[0]++;
            return markRevoked(v, now, reason);
          }
          return v;
        });
    return affected[0];
  }

  @Override
  public List<RefreshTokenRecord> findByUserHandle(UserHandle userHandle) {
    List<RefreshTokenRecord> out = new ArrayList<>();
    for (RefreshTokenRecord r : byRefreshId.values()) {
      if (r.userHandle().equals(userHandle)) {
        out.add(r);
      }
    }
    out.sort(Comparator.comparing(RefreshTokenRecord::issuedAt));
    return List.copyOf(out);
  }

  @Override
  public List<RefreshTokenRecord> findByFamilyId(String familyId) {
    List<RefreshTokenRecord> out = new ArrayList<>();
    for (RefreshTokenRecord r : byRefreshId.values()) {
      if (r.familyId().equals(familyId)) {
        out.add(r);
      }
    }
    out.sort(Comparator.comparing(RefreshTokenRecord::issuedAt));
    return List.copyOf(out);
  }

  @Override
  public int deleteExpiredBefore(Instant cutoff) {
    int[] removed = {0};
    byRefreshId
        .entrySet()
        .removeIf(
            e -> {
              RefreshTokenRecord r = e.getValue();
              if (r.expiresAt().isBefore(cutoff)
                  && (r.usedAt().filter(t -> t.isBefore(cutoff)).isPresent()
                      || r.revokedAt().filter(t -> t.isBefore(cutoff)).isPresent())) {
                removed[0]++;
                return true;
              }
              return false;
            });
    return removed[0];
  }

  private static RefreshTokenRecord markUsed(RefreshTokenRecord r, Instant now) {
    return new RefreshTokenRecord(
        r.refreshId(),
        r.tokenHash(),
        r.userHandle(),
        r.audience(),
        r.deviceId(),
        r.familyId(),
        r.parentRefreshId(),
        r.issuedAt(),
        r.expiresAt(),
        Optional.of(now),
        r.revokedAt(),
        r.revokedReason(),
        r.amr());
  }

  private static RefreshTokenRecord markRevoked(
      RefreshTokenRecord r, Instant now, RevokeReason reason) {
    return new RefreshTokenRecord(
        r.refreshId(),
        r.tokenHash(),
        r.userHandle(),
        r.audience(),
        r.deviceId(),
        r.familyId(),
        r.parentRefreshId(),
        r.issuedAt(),
        r.expiresAt(),
        r.usedAt(),
        Optional.of(now),
        Optional.of(reason),
        r.amr());
  }
}
