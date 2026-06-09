// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.testkit.InMemoryRefreshTokenRepository;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** Verifies the user-deletion bridge revokes every refresh family with {@code USER_DELETED}. */
class RefreshTokenServiceDeletionListenerTest {

  private static final Instant NOW = Instant.parse("2026-05-16T12:00:00Z");
  private static final UserHandle USER = UserHandle.of(new byte[] {1, 2, 3});
  private static final List<String> AMR = List.of("pkauth");

  private final InMemoryRefreshTokenRepository repository = new InMemoryRefreshTokenRepository();
  private final RefreshTokenService service =
      new RefreshTokenService(
          repository,
          RefreshTokenConfig.defaults(),
          ClockProvider.fromClock(Clock.fixed(NOW, ZoneOffset.UTC)),
          new SecureRandom());

  @Test
  void onUserDeletedRevokesEveryFamilyWithUserDeletedReason() {
    service.issue(USER, "web", Optional.empty(), AMR);
    service.issue(USER, "cli", Optional.empty(), AMR);

    new RefreshTokenServiceDeletionListener(service).onUserDeleted(USER);

    assertThat(repository.findByUserHandle(USER))
        .isNotEmpty()
        .allSatisfy(
            r -> {
              assertThat(r.revokedAt()).isPresent();
              assertThat(r.revokedReason()).hasValue(RevokeReason.USER_DELETED);
            });
  }

  @Test
  void constructorRejectsNullService() {
    assertThatThrownBy(() -> new RefreshTokenServiceDeletionListener(null))
        .isInstanceOf(NullPointerException.class);
  }
}
