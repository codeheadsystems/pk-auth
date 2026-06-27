// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.lifecycle;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import org.junit.jupiter.api.Test;

class UserDeletionServiceTest {

  private static final UserHandle USER = UserHandle.of(new byte[] {1, 2, 3});

  @Test
  void runsEveryListenerInOrder() {
    List<String> calls = new ArrayList<>();
    UserDeletionListener a = recording("A", calls);
    UserDeletionListener b = recording("B", calls);
    UserDeletionListener c = recording("C", calls);

    UserDeletionResult result = new UserDeletionService(List.of(a, b, c)).deleteUser(USER);

    assertThat(calls).containsExactly("A", "B", "C");
    assertThat(result.succeeded()).isEqualTo(3);
    assertThat(result.failed()).isZero();
    assertThat(result.failedListenerNames()).isEmpty();
    assertThat(result.allSucceeded()).isTrue();
  }

  @Test
  void aFailingListenerDoesNotStopRemaining() {
    List<String> calls = new ArrayList<>();
    UserDeletionListener a = recording("A", calls);
    UserDeletionListener boom =
        new UserDeletionListener() {
          @Override
          public void onUserDeleted(UserHandle userHandle) {
            calls.add("BOOM");
            throw new IllegalStateException("simulated");
          }

          @Override
          public String name() {
            return "Boom";
          }
        };
    UserDeletionListener c = recording("C", calls);

    UserDeletionResult result = new UserDeletionService(List.of(a, boom, c)).deleteUser(USER);

    assertThat(calls).containsExactly("A", "BOOM", "C");
    assertThat(result.succeeded()).isEqualTo(2);
    assertThat(result.failed()).isEqualTo(1);
    assertThat(result.failedListenerNames()).containsExactly("Boom");
    assertThat(result.allSucceeded()).isFalse();
  }

  @Test
  void resultRejectsMismatchedFailedCount() {
    assertThatThrownBy(() -> new UserDeletionResult(0, 1, List.of()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void credentialListenerForwardsToRepository() {
    StubCredentialRepository repo = new StubCredentialRepository();
    new CredentialRepositoryDeletionListener(repo).onUserDeleted(USER);
    assertThat(repo.deletedFor).containsExactly(USER);
  }

  @Test
  void backupCodeListenerForwardsToRepository() {
    StubBackupCodeRepository repo = new StubBackupCodeRepository();
    new BackupCodeRepositoryDeletionListener(repo).onUserDeleted(USER);
    assertThat(repo.deletedFor).containsExactly(USER);
  }

  @Test
  void otpListenerForwardsToRepository() {
    StubOtpRepository repo = new StubOtpRepository();
    new OtpRepositoryDeletionListener(repo).onUserDeleted(USER);
    assertThat(repo.deletedFor).containsExactly(USER);
  }

  // -- Helpers -----------------------------------------------------------------------------

  private static UserDeletionListener recording(String name, List<String> calls) {
    return new UserDeletionListener() {
      @Override
      public void onUserDeleted(UserHandle userHandle) {
        calls.add(name);
      }

      @Override
      public String name() {
        return name;
      }
    };
  }

  private static final class StubCredentialRepository implements CredentialRepository {
    final List<UserHandle> deletedFor = new ArrayList<>();

    @Override
    public void save(CredentialRecord record) {}

    @Override
    public Optional<CredentialRecord> findByCredentialId(CredentialId credentialId) {
      return Optional.empty();
    }

    @Override
    public List<CredentialRecord> findByUserHandle(UserHandle userHandle) {
      return List.of();
    }

    @Override
    public void updateSignCount(CredentialId credentialId, long newCount, Instant lastUsedAt) {}

    @Override
    public void updateLabel(UserHandle userHandle, CredentialId credentialId, String label) {}

    @Override
    public void delete(UserHandle userHandle, CredentialId credentialId) {}

    @Override
    public int deleteByUserHandle(UserHandle userHandle) {
      deletedFor.add(userHandle);
      return 0;
    }
  }

  private static final class StubBackupCodeRepository implements BackupCodeRepository {
    final List<UserHandle> deletedFor = new ArrayList<>();

    @Override
    public void save(StoredBackupCode code) {}

    @Override
    public List<StoredBackupCode> findByUserHandle(UserHandle userHandle) {
      return List.of();
    }

    @Override
    public boolean consume(UserHandle userHandle, String codeId, Instant consumedAt) {
      return false;
    }

    @Override
    public void deleteByUserHandle(UserHandle userHandle) {
      deletedFor.add(userHandle);
    }

    @Override
    public void replaceAll(UserHandle userHandle, List<StoredBackupCode> records) {}
  }

  private static final class StubOtpRepository implements OtpRepository {
    final List<UserHandle> deletedFor = new ArrayList<>();

    @Override
    public void save(StoredOtp otp) {}

    @Override
    public Optional<StoredOtp> findLatestActive(
        UserHandle userHandle, String phoneE164, Instant now) {
      return Optional.empty();
    }

    @Override
    public OptionalInt incrementAttempts(UserHandle userHandle, String otpId) {
      return OptionalInt.empty();
    }

    @Override
    public boolean consume(UserHandle userHandle, String otpId) {
      return false;
    }

    @Override
    public int countSince(UserHandle userHandle, String phoneE164, Instant since) {
      return 0;
    }

    @Override
    public int deleteByUserHandle(UserHandle userHandle) {
      deletedFor.add(userHandle);
      return 0;
    }
  }
}
