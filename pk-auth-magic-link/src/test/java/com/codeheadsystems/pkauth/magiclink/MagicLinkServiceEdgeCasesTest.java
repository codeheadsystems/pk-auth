// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.magiclink;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.jwt.JwtConfig;
import com.codeheadsystems.pkauth.jwt.JwtKeyset;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.codeheadsystems.pkauth.testkit.InMemoryUserLookup;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * Edge cases not covered by {@link MagicLinkServiceTest}: the email-binding feature added for the
 * #9 fix, and the consumed-JTI TTL behaviour added for #8.
 */
class MagicLinkServiceEdgeCasesTest {

  private static final Instant NOW = Instant.parse("2026-05-14T12:00:00Z");
  private static final String ISSUER = "https://pkauth.example.com";
  private static final String AUDIENCE = "https://app.example.com";
  private static final String BASE_URL = "https://app.example.com/auth/magic";

  /** UserLookup that maps users to a bound email so we can test the binding check. */
  private static final class BoundEmailUserLookup implements UserLookup {
    private final InMemoryUserLookup delegate = new InMemoryUserLookup();
    private final Map<UserHandle, String> emails = new java.util.HashMap<>();

    UserHandle register(String username, String displayName, String email) {
      UserHandle uh = delegate.register(username, displayName);
      emails.put(uh, email);
      return uh;
    }

    @Override
    public Optional<UserHandle> findHandleByUsername(String username) {
      return delegate.findHandleByUsername(username);
    }

    @Override
    public Optional<UserView> findViewByHandle(UserHandle handle) {
      return delegate.findViewByHandle(handle);
    }

    @Override
    public UserHandle getOrCreateHandle(String username) {
      return delegate.getOrCreateHandle(username);
    }

    @Override
    public Optional<String> emailFor(UserHandle handle) {
      return Optional.ofNullable(emails.get(handle));
    }
  }

  private MagicLinkService buildService(UserLookup lookup, Duration consumedJtiTtl) {
    return buildService(lookup, consumedJtiTtl, (to, subj, body) -> {});
  }

  private MagicLinkService buildService(
      UserLookup lookup, Duration consumedJtiTtl, EmailSender emailSender) {
    byte[] secret = new byte[32];
    new SecureRandom().nextBytes(secret);
    JwtKeyset keyset = JwtKeyset.hs256(secret);
    JwtConfig config = JwtConfig.defaults(ISSUER, AUDIENCE);
    ClockProvider clock = ClockProvider.fromClock(Clock.fixed(NOW, ZoneOffset.UTC));
    return MagicLinkService.create(
        MagicLinkService.Dependencies.of(
            new PkAuthJwtIssuer(config, keyset, clock),
            new PkAuthJwtValidator(config, keyset, clock),
            emailSender,
            lookup,
            clock),
        new MagicLinkService.Config(
            BASE_URL,
            5,
            new MagicLinkService.InMemoryRateLimiter(Duration.ofHours(1)),
            consumedJtiTtl));
  }

  /**
   * Captures the emailed magic-link URL so a test can recover the token. Since 2.3.0 {@link
   * MagicLinkService.SendResult.Sent} carries only the jti, so — as for a real recipient — the
   * emailed link is the only route to the token.
   */
  private static final class CapturingEmailSender implements EmailSender {
    private String lastBody = "";

    @Override
    public void send(String to, String subject, String body) {
      lastBody = body;
    }

    String lastToken() {
      int marker = lastBody.indexOf("?t=");
      assertThat(marker).isNotNegative();
      return URLDecoder.decode(lastBody.substring(marker + "?t=".length()), StandardCharsets.UTF_8);
    }
  }

  @Test
  void emailMatchingBoundValueProceeds() {
    BoundEmailUserLookup lookup = new BoundEmailUserLookup();
    UserHandle user = lookup.register("alice", "Alice", "alice@example.com");
    MagicLinkService service = buildService(lookup, MagicLinkService.DEFAULT_CONSUMED_JTI_TTL);

    MagicLinkService.SendResult result = service.startEmailVerification(user, "alice@example.com");

    assertThat(result).isInstanceOf(MagicLinkService.SendResult.Sent.class);
  }

  @Test
  void emailNotMatchingBoundValueIsRejected() {
    BoundEmailUserLookup lookup = new BoundEmailUserLookup();
    UserHandle user = lookup.register("alice", "Alice", "alice@example.com");
    MagicLinkService service = buildService(lookup, MagicLinkService.DEFAULT_CONSUMED_JTI_TTL);

    MagicLinkService.SendResult result =
        service.startEmailVerification(user, "attacker@evil.example");

    assertThat(result).isInstanceOf(MagicLinkService.SendResult.EmailMismatch.class);
  }

  @Test
  void emailNotBoundFallsBackToCallerSuppliedWithWarning() {
    // Default UserLookup#emailFor returns Optional.empty() — caller-supplied email passes through.
    InMemoryUserLookup lookup = new InMemoryUserLookup();
    UserHandle user = lookup.register("alice", "Alice");
    MagicLinkService service = buildService(lookup, MagicLinkService.DEFAULT_CONSUMED_JTI_TTL);

    MagicLinkService.SendResult result =
        service.startEmailVerification(user, "trust-me-bro@example.com");

    assertThat(result).isInstanceOf(MagicLinkService.SendResult.Sent.class);
  }

  @Test
  void singleUseHoldsAcrossManyConsumeAttemptsWithinTtl() {
    InMemoryUserLookup lookup = new InMemoryUserLookup();
    UserHandle user = lookup.register("alice", "Alice");
    CapturingEmailSender emails = new CapturingEmailSender();
    MagicLinkService service = buildService(lookup, Duration.ofMinutes(30), emails);

    service.startEmailVerification(user, "a@example.com");
    String token = emails.lastToken();
    assertThat(service.finishVerification(token))
        .isInstanceOf(MagicLinkService.ConsumeResult.Success.class);

    List<MagicLinkService.ConsumeResult> attempts = new ArrayList<>();
    for (int i = 0; i < 20; i++) {
      attempts.add(service.finishVerification(token));
    }
    assertThat(attempts).allMatch(r -> r instanceof MagicLinkService.ConsumeResult.AlreadyConsumed);
  }
}
