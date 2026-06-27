// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory {@link OtpRepository}. */
public final class InMemoryOtpRepository implements OtpRepository {

  private final Map<String, StoredOtp> byId = new ConcurrentHashMap<>();

  public InMemoryOtpRepository() {}

  @Override
  public void save(StoredOtp otp) {
    byId.put(otp.otpId(), otp);
  }

  @Override
  public Optional<StoredOtp> findLatestActive(
      UserHandle userHandle, String phoneE164, Instant now) {
    return byId.values().stream()
        .filter(o -> o.userHandle().equals(userHandle))
        .filter(o -> o.phoneE164().equals(phoneE164))
        .filter(o -> !o.consumed())
        .filter(o -> o.expiresAt().isAfter(now))
        .max(Comparator.comparing(StoredOtp::createdAt));
  }

  @Override
  public OptionalInt incrementAttempts(UserHandle userHandle, String otpId) {
    // Use a sentinel of -1 to distinguish "no matching row" from a real attempt count, since the
    // lambda can't differentiate empty Optional vs. zero via primitive int. After the compute,
    // -1 means computeIfPresent never matched (or the userHandle guard rejected the row).
    int[] newAttempts = {-1};
    byId.computeIfPresent(
        otpId,
        (k, existing) -> {
          if (!existing.userHandle().equals(userHandle)) {
            return existing;
          }
          int updated = existing.attempts() + 1;
          newAttempts[0] = updated;
          return new StoredOtp(
              existing.otpId(),
              existing.userHandle(),
              existing.phoneE164(),
              existing.hashedCode(),
              updated,
              existing.maxAttempts(),
              existing.consumed(),
              existing.createdAt(),
              existing.expiresAt());
        });
    return newAttempts[0] < 0 ? OptionalInt.empty() : OptionalInt.of(newAttempts[0]);
  }

  @Override
  public boolean consume(UserHandle userHandle, String otpId) {
    // Atomic compute: only one caller observes the unconsumed→consumed transition. Concurrent
    // verifiers see false and the OtpService treats that as "already consumed / no match".
    boolean[] flipped = {false};
    byId.computeIfPresent(
        otpId,
        (k, existing) -> {
          if (!existing.userHandle().equals(userHandle) || existing.consumed()) {
            return existing;
          }
          flipped[0] = true;
          return new StoredOtp(
              existing.otpId(),
              existing.userHandle(),
              existing.phoneE164(),
              existing.hashedCode(),
              existing.attempts(),
              existing.maxAttempts(),
              true,
              existing.createdAt(),
              existing.expiresAt());
        });
    return flipped[0];
  }

  @Override
  public int countSince(UserHandle userHandle, String phoneE164, Instant since) {
    return (int)
        byId.values().stream()
            .filter(o -> o.userHandle().equals(userHandle))
            .filter(o -> o.phoneE164().equals(phoneE164))
            .filter(o -> !o.createdAt().isBefore(since))
            .count();
  }

  @Override
  public int deleteByUserHandle(UserHandle userHandle) {
    int[] removed = {0};
    byId.entrySet()
        .removeIf(
            e -> {
              if (e.getValue().userHandle().equals(userHandle)) {
                removed[0]++;
                return true;
              }
              return false;
            });
    return removed[0];
  }
}
