// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.magiclink;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.jwt.AuthMethod;
import com.codeheadsystems.pkauth.jwt.JwtClaims;
import com.codeheadsystems.pkauth.jwt.JwtVerificationResult;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.ratelimit.InMemoryWindowCounter;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.ConsumedJtiStore;
import com.codeheadsystems.pkauth.spi.MessageFormatter;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.nimbusds.jwt.SignedJWT;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sends and consumes magic-link tokens. Two flows per brief §6.4:
 *
 * <ul>
 *   <li>Email verification — the {@code pkauth.purpose} claim is {@code email-verify}.
 *   <li>Passwordless login — the {@code pkauth.purpose} claim is {@code login}.
 * </ul>
 *
 * <p>Single-use is enforced by recording consumed JTI values in a {@link ConsumedJtiStore} whose
 * entries expire after {@code consumedJtiTtl} (default: {@link #DEFAULT_CONSUMED_JTI_TTL}). The
 * SPI's default in-process implementation ({@link InMemoryConsumedJtiStore}) is dev/single-instance
 * only — multi-replica deployments MUST inject a shared (Redis/DB-backed) store, otherwise a token
 * redeemed on one replica can be redeemed again on another within its TTL window. The service logs
 * a startup WARN when the in-memory default is wired. Rate limiting (brief §6.4 — N emails per
 * user/purpose per hour) is tracked through {@link MagicLinkRateLimiter}, which follows the same
 * pattern (dev-only in-process default; production replaces with a shared implementation).
 *
 * <p>Construct via {@link #create(Dependencies, Config)} (or {@link #create(Dependencies, String)}
 * for the all-default case). Required collaborators live in {@link Dependencies}; tunables (rate
 * limit, consumed-JTI TTL, base URL) live in {@link Config}.
 */
public final class MagicLinkService {

  /** Wire value of the email-verify purpose claim. */
  public static final String PURPOSE_EMAIL_VERIFY = "email-verify";

  /** Wire value of the login purpose claim. */
  public static final String PURPOSE_LOGIN = "login";

  /** JWT claim name carrying the magic-link purpose. */
  public static final String CLAIM_PURPOSE = "pkauth.purpose";

  /** JWT claim name carrying the email address (verification flow only). */
  public static final String CLAIM_EMAIL = "pkauth.email";

  /** Default TTL of an issued magic-link JWT. */
  public static final Duration DEFAULT_TTL = Duration.ofMinutes(15);

  /**
   * Default TTL for the consumed-JTI cache. Set comfortably larger than {@link #DEFAULT_TTL} so a
   * JWT that's already expired can't be replayed even if the validator's clock-skew tolerance
   * accepts it briefly after expiry.
   */
  public static final Duration DEFAULT_CONSUMED_JTI_TTL = Duration.ofMinutes(30);

  /** Default rate limit: 5 emails per (user, purpose) per hour. */
  public static final int DEFAULT_RATE_LIMIT = 5;

  /** Default rate-limit window. */
  public static final Duration DEFAULT_RATE_WINDOW = Duration.ofHours(1);

  /** Result of a send attempt. */
  public sealed interface SendResult {
    /** Email was dispatched. */
    record Sent(String tokenJti) implements SendResult {}

    /** Rate limit hit. */
    record RateLimited(int countInWindow) implements SendResult {}

    /** No user matched the supplied identifier (login flow only). */
    record UserNotFound() implements SendResult {}

    /**
     * The caller-supplied email does not match the one bound to the user via {@link
     * UserLookup#emailFor(UserHandle)}. Returned only when the host has implemented {@code
     * emailFor}; otherwise the binding check is skipped (with a warning log) and the send proceeds.
     */
    record EmailMismatch() implements SendResult {}
  }

  /** Result of a consume attempt. */
  public sealed interface ConsumeResult {
    /** Token verified, was unconsumed, and is now consumed. */
    record Success(UserHandle userHandle, String purpose, @Nullable String email)
        implements ConsumeResult {}

    /** JWT verification failed (bad signature, expired, wrong issuer, etc.). */
    record Invalid(JwtVerificationResult reason) implements ConsumeResult {}

    /** Token already consumed earlier. */
    record AlreadyConsumed() implements ConsumeResult {}

    /**
     * Token is otherwise valid but was minted for a different {@code pkauth.purpose} than the
     * endpoint requires (e.g. a {@code login} token presented to the email-verification flow). The
     * single-use JTI is deliberately <em>not</em> consumed in this case, so the token stays usable
     * at its intended endpoint.
     *
     * @since 2.1.0
     */
    record WrongPurpose(String expectedPurpose, String actualPurpose) implements ConsumeResult {}
  }

  /** Pluggable rate limiter — defaults to an in-process Caffeine counter. */
  public interface MagicLinkRateLimiter {
    /** Returns the current count and whether a new send is allowed. */
    int countAndIncrement(UserHandle user, String purpose, Instant now);
  }

  private static final Logger LOG = LoggerFactory.getLogger(MagicLinkService.class);

  private final PkAuthJwtIssuer issuer;
  private final PkAuthJwtValidator validator;
  private final EmailSender emailSender;
  private final UserLookup userLookup;
  private final ClockProvider clockProvider;
  private final String baseUrl;
  private final int rateLimit;
  private final MagicLinkRateLimiter rateLimiter;
  private final ConsumedJtiStore consumedJtiStore;
  private final Duration consumedJtiTtl;
  private final MessageFormatter<MagicLinkContext, MagicLinkMessage> messageFormatter;

  private MagicLinkService(Dependencies deps, Config config) {
    this.issuer = deps.issuer();
    this.validator = deps.validator();
    this.emailSender = deps.emailSender();
    this.userLookup = deps.userLookup();
    this.clockProvider = deps.clockProvider();
    this.consumedJtiStore = deps.consumedJtiStore();
    this.messageFormatter = deps.messageFormatter();
    this.baseUrl = config.baseUrl();
    this.rateLimit = config.rateLimit();
    this.rateLimiter = config.rateLimiter();
    this.consumedJtiTtl = config.consumedJtiTtl();
    if (consumedJtiStore instanceof InMemoryConsumedJtiStore) {
      LOG.warn(
          "magiclink.consumed-jti-store InMemoryConsumedJtiStore wired — FOR DEV /"
              + " SINGLE-INSTANCE USE ONLY. Production deployments with more than one replica"
              + " MUST inject a shared (Redis/DB-backed) ConsumedJtiStore via the"
              + " MagicLinkService.Dependencies record, otherwise a captured magic-link can be"
              + " replayed across replicas within its TTL window.");
    }
  }

  /**
   * Canonical factory: required collaborators in {@link Dependencies}, tunables in {@link Config}.
   *
   * @since 0.9.1
   */
  public static MagicLinkService create(Dependencies deps, Config config) {
    Objects.requireNonNull(deps, "deps");
    Objects.requireNonNull(config, "config");
    return new MagicLinkService(deps, config);
  }

  /**
   * Convenience overload that builds a {@link Config} carrying the supplied {@code baseUrl} and the
   * documented defaults for every other tunable. The {@code baseUrl} has no library default — it is
   * a host-specific URL prefix.
   *
   * @since 0.9.1
   */
  public static MagicLinkService create(Dependencies deps, String baseUrl) {
    Objects.requireNonNull(deps, "deps");
    return new MagicLinkService(deps, Config.defaults(baseUrl));
  }

  /**
   * Sends a verification email containing a magic link tied to {@code email}. If the host has
   * implemented {@link UserLookup#emailFor(UserHandle)}, the supplied {@code email} must equal the
   * bound value (constant-time compare) — otherwise a caller could mint a "verified" claim for an
   * arbitrary address. If the host has not implemented {@code emailFor}, the binding check is
   * skipped (with a warning log) and the send proceeds.
   *
   * @since 0.9.1
   */
  public SendResult startEmailVerification(UserHandle user, String email) {
    Objects.requireNonNull(user, "user");
    Objects.requireNonNull(email, "email");
    Optional<String> bound = userLookup.emailFor(user);
    if (bound.isPresent()) {
      byte[] expected = bound.get().getBytes(StandardCharsets.UTF_8);
      byte[] actual = email.getBytes(StandardCharsets.UTF_8);
      if (!MessageDigest.isEqual(expected, actual)) {
        LOG.warn("magiclink.send email-mismatch user={} purpose={}", user, PURPOSE_EMAIL_VERIFY);
        return new SendResult.EmailMismatch();
      }
    } else {
      LOG.warn(
          "magiclink.send email-not-bound user={} — UserLookup#emailFor returned empty; the"
              + " library cannot verify the caller-supplied address belongs to this user. Host"
              + " apps that store user emails should override UserLookup#emailFor.",
          user);
    }
    int count = rateLimiter.countAndIncrement(user, PURPOSE_EMAIL_VERIFY, clockProvider.now());
    if (count > rateLimit) {
      LOG.info(
          "magiclink.send rate-limited user={} purpose={} count={}",
          user,
          PURPOSE_EMAIL_VERIFY,
          count);
      return new SendResult.RateLimited(count);
    }
    String token = issue(user, PURPOSE_EMAIL_VERIFY, Map.of(CLAIM_EMAIL, email));
    String url = baseUrl + "?t=" + URLEncoder.encode(token, StandardCharsets.UTF_8);
    MagicLinkMessage message =
        messageFormatter.format(new MagicLinkContext(user, email, url, PURPOSE_EMAIL_VERIFY));
    emailSender.send(email, message.subject(), message.body());
    LOG.info("magiclink.send issued user={} purpose={}", user, PURPOSE_EMAIL_VERIFY);
    return new SendResult.Sent(token);
  }

  /**
   * Sends a login email to the user with the supplied username.
   *
   * <p><strong>Privacy invariant (result-shape only):</strong> this method ALWAYS returns {@link
   * SendResult.Sent}, regardless of whether the supplied username exists in the system. When no
   * user is found the method returns early (skipping JWT issuance and email dispatch) but returns
   * the same {@code Sent} shape as a successful send, so the response body never reveals whether an
   * account exists. Callers MUST NOT rely on a {@link SendResult.UserNotFound} outcome from this
   * method — that variant is produced only by signup flows where confirming account non-existence
   * is intentional.
   *
   * <p><strong>This method is NOT constant-time.</strong> The not-found path returns before JWT
   * issuance and the (typically blocking) email dispatch, so a known username incurs measurably
   * more latency than an unknown one; an attacker who can time responses can still enumerate
   * accounts. Equalising this is impractical at the library layer because SMTP/transport latency
   * dominates and varies — hosts that need timing-side-channel resistance should front this with a
   * uniform-latency wrapper or rate-limit and monitor for enumeration probing.
   *
   * @since 0.9.1
   */
  public SendResult startLogin(String username, String email) {
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(email, "email");
    Optional<UserHandle> resolved = userLookup.findHandleByUsername(username);
    if (resolved.isEmpty()) {
      // Do NOT surface UserNotFound to callers — that would enable account enumeration.
      // Skip JWT issuance and email dispatch silently and return Sent.
      LOG.debug("magiclink.send user-not-found (suppressed) username={}", username);
      return new SendResult.Sent("");
    }
    UserHandle user = resolved.get();
    int count = rateLimiter.countAndIncrement(user, PURPOSE_LOGIN, clockProvider.now());
    if (count > rateLimit) {
      return new SendResult.RateLimited(count);
    }
    String token = issue(user, PURPOSE_LOGIN, Map.of());
    String url = baseUrl + "?t=" + URLEncoder.encode(token, StandardCharsets.UTF_8);
    MagicLinkMessage message =
        messageFormatter.format(new MagicLinkContext(user, email, url, PURPOSE_LOGIN));
    emailSender.send(email, message.subject(), message.body());
    return new SendResult.Sent(token);
  }

  /**
   * Verifies and consumes a magic-link token. Used by both the email-verify and login flows; the
   * purpose distinction lives in the JWT's {@code pkauth.purpose} claim.
   *
   * @since 0.9.1
   */
  public ConsumeResult finishVerification(String token) {
    return finishVerification(token, null);
  }

  /**
   * Verifies and consumes a magic-link token, additionally enforcing that its {@code
   * pkauth.purpose} claim equals {@code requiredPurpose}. This closes a cross-purpose token
   * confusion: without it, a token minted for one flow (e.g. {@link #PURPOSE_LOGIN}) satisfies
   * another flow's consume check (e.g. {@link #PURPOSE_EMAIL_VERIFY}), letting one ceremony's token
   * stand in for another. The purpose is checked <em>before</em> the single-use JTI is consumed, so
   * a cross-purpose attempt does not burn the token at its legitimate endpoint.
   *
   * @param token the magic-link JWT
   * @param requiredPurpose the purpose the caller demands, or {@code null} to accept any purpose
   *     (the caller then inspects {@link ConsumeResult.Success#purpose()} itself)
   * @return the consume outcome
   * @since 2.1.0
   */
  public ConsumeResult finishVerification(String token, @Nullable String requiredPurpose) {
    Objects.requireNonNull(token, "token");
    JwtVerificationResult verification = validator.validate(token);
    if (!(verification instanceof JwtVerificationResult.Success success)) {
      return new ConsumeResult.Invalid(verification);
    }
    JwtClaims claims = success.claims();
    String purpose = stringClaim(claims.additionalClaims(), CLAIM_PURPOSE);
    if (purpose == null) {
      return new ConsumeResult.Invalid(new JwtVerificationResult.MissingClaim(CLAIM_PURPOSE));
    }
    if (requiredPurpose != null && !requiredPurpose.equals(purpose)) {
      LOG.warn(
          "magiclink.verify wrong-purpose user={} expected={} actual={}",
          claims.userHandle(),
          requiredPurpose,
          purpose);
      return new ConsumeResult.WrongPurpose(requiredPurpose, purpose);
    }
    String email = stringClaim(claims.additionalClaims(), CLAIM_EMAIL);

    // Single-use: the JTI is opaque; we don't have direct access to it through JwtClaims, so we
    // re-parse the JWT just for the id. Cheap because we already validated it above. The store's
    // tryConsume contract is atomic — concurrent verifies of the same JTI will see exactly one
    // true return, with the loser observing AlreadyConsumed.
    String jti = jtiOf(token);
    if (!consumedJtiStore.tryConsume(jti, consumedJtiTtl)) {
      return new ConsumeResult.AlreadyConsumed();
    }
    return new ConsumeResult.Success(claims.userHandle(), purpose, email);
  }

  private String issue(UserHandle user, String purpose, Map<String, String> extras) {
    Map<String, Object> additional = new HashMap<>(extras);
    additional.put(CLAIM_PURPOSE, purpose);
    JwtClaims claims = new JwtClaims(user, AuthMethod.MAGIC_LINK, null, List.of("eml"), additional);
    return issuer.issue(claims);
  }

  private static @Nullable String stringClaim(@Nullable Map<String, Object> map, String name) {
    if (map == null) {
      return null;
    }
    Object v = map.get(name);
    return v == null ? null : v.toString();
  }

  private static String jtiOf(String token) {
    try {
      return SignedJWT.parse(token).getJWTClaimsSet().getJWTID();
    } catch (ParseException e) {
      throw new IllegalStateException("Unable to extract jti from verified token", e);
    }
  }

  /**
   * Canonical holder of the required collaborators for {@link MagicLinkService}.
   *
   * <p>The {@code consumedJtiStore} enforces single-use; multi-replica deployments MUST supply a
   * shared (Redis/DB-backed) implementation. The {@code messageFormatter} renders the {@link
   * MagicLinkContext} (user, recipient, URL, purpose) into a {@link MagicLinkMessage} that is
   * passed verbatim to {@link EmailSender#send(String, String, String)}; supply a host-specific
   * formatter to brand or localize the email copy without forking this service.
   *
   * @since 0.9.1
   */
  public record Dependencies(
      PkAuthJwtIssuer issuer,
      PkAuthJwtValidator validator,
      EmailSender emailSender,
      UserLookup userLookup,
      ClockProvider clockProvider,
      ConsumedJtiStore consumedJtiStore,
      MessageFormatter<MagicLinkContext, MagicLinkMessage> messageFormatter) {
    /** Compact constructor — enforces non-null on every collaborator. */
    public Dependencies {
      Objects.requireNonNull(issuer, "issuer");
      Objects.requireNonNull(validator, "validator");
      Objects.requireNonNull(emailSender, "emailSender");
      Objects.requireNonNull(userLookup, "userLookup");
      Objects.requireNonNull(clockProvider, "clockProvider");
      Objects.requireNonNull(consumedJtiStore, "consumedJtiStore");
      Objects.requireNonNull(messageFormatter, "messageFormatter");
    }

    /**
     * Convenience factory that wires {@link InMemoryConsumedJtiStore} (sized to {@link
     * #DEFAULT_CONSUMED_JTI_TTL}) and {@link DefaultMagicLinkFormatter}. Suitable only for dev /
     * single-instance deployments.
     *
     * @since 0.9.1
     */
    public static Dependencies of(
        PkAuthJwtIssuer issuer,
        PkAuthJwtValidator validator,
        EmailSender emailSender,
        UserLookup userLookup,
        ClockProvider clockProvider) {
      return new Dependencies(
          issuer,
          validator,
          emailSender,
          userLookup,
          clockProvider,
          new InMemoryConsumedJtiStore(DEFAULT_CONSUMED_JTI_TTL),
          new DefaultMagicLinkFormatter());
    }
  }

  /**
   * Tunable configuration for {@link MagicLinkService}.
   *
   * <p>{@code baseUrl} is required (no library default) — it is the host-specific URL prefix
   * inserted into outbound emails. Every other field has a documented default exposed via {@link
   * #defaults(String)}.
   *
   * <p>The default {@link MagicLinkRateLimiter} is {@link InMemoryRateLimiter} — DEV /
   * SINGLE-INSTANCE ONLY. Multi-replica deployments MUST replace it with a shared (Redis/DB-backed)
   * implementation.
   *
   * <p><strong>{@code consumedJtiTtl} must be at least as long as the magic-link JWT's
   * TTL.</strong> Single-use is enforced by retaining each consumed JTI for {@code consumedJtiTtl};
   * if that retention is shorter than the token's own validity, a still-unexpired token becomes
   * redeemable again once its JTI entry is evicted, defeating single-use. The defaults are safe
   * (30m retention vs the 15m default token TTL); keep this invariant if you tune either value.
   * This is not enforced at construction because the token TTL is owned by the JWT issuer (and may
   * vary per audience), not by this config.
   *
   * @since 0.9.1
   */
  public record Config(
      String baseUrl, int rateLimit, MagicLinkRateLimiter rateLimiter, Duration consumedJtiTtl) {
    /**
     * Compact constructor — enforces non-null on every field, and rejects a {@code baseUrl} that
     * isn't an http(s) URL or that carries whitespace / CRLF (which would enable header-splitting
     * if the value flowed into a response header). Hosts running in dev mode may pass {@code
     * http://}; production deployments are expected to pass {@code https://}.
     */
    public Config {
      Objects.requireNonNull(baseUrl, "baseUrl");
      Objects.requireNonNull(rateLimiter, "rateLimiter");
      Objects.requireNonNull(consumedJtiTtl, "consumedJtiTtl");
      validateBaseUrl(baseUrl);
      if (rateLimit < 1) {
        throw new IllegalArgumentException("rateLimit must be at least 1");
      }
      if (consumedJtiTtl.isZero() || consumedJtiTtl.isNegative()) {
        throw new IllegalArgumentException("consumedJtiTtl must be strictly positive");
      }
    }

    private static void validateBaseUrl(String baseUrl) {
      if (!(baseUrl.startsWith("https://") || baseUrl.startsWith("http://"))) {
        throw new IllegalArgumentException(
            "baseUrl must start with https:// (or http:// in dev mode): " + baseUrl);
      }
      for (int i = 0; i < baseUrl.length(); i++) {
        char c = baseUrl.charAt(i);
        if (c == '\r' || c == '\n' || Character.isWhitespace(c)) {
          throw new IllegalArgumentException(
              "baseUrl must not contain whitespace or CRLF characters");
        }
      }
    }

    /**
     * Returns a {@link Config} with all-default tunables and the supplied {@code baseUrl}.
     *
     * @since 0.9.1
     */
    public static Config defaults(String baseUrl) {
      return new Config(
          baseUrl,
          DEFAULT_RATE_LIMIT,
          new InMemoryRateLimiter(DEFAULT_RATE_WINDOW),
          DEFAULT_CONSUMED_JTI_TTL);
    }
  }

  /**
   * Simple in-memory rate limiter backed by {@link InMemoryWindowCounter}.
   *
   * <p><strong>FOR DEV / SINGLE-INSTANCE USE ONLY.</strong> Production deployments MUST replace
   * this with a shared (Redis/DB-backed) {@link MagicLinkRateLimiter} implementation, otherwise
   * per-replica rate limits multiply by the cluster size. For example, with a limit of 5 emails per
   * hour and a 3-node cluster, an attacker can send up to 15 emails per hour because each replica
   * tracks its own independent counter. Wire a production-grade implementation via the {@link
   * Config} record passed to {@link #create(Dependencies, Config)}.
   *
   * @since 0.9.1
   */
  public static final class InMemoryRateLimiter implements MagicLinkRateLimiter {
    private static final Logger RATE_LOG = LoggerFactory.getLogger(InMemoryRateLimiter.class);

    private final InMemoryWindowCounter counter;

    public InMemoryRateLimiter(Duration window) {
      RATE_LOG.info(
          "magiclink.rate-limiter InMemoryRateLimiter instantiated — FOR DEV / SINGLE-INSTANCE"
              + " USE ONLY. Production deployments MUST replace this with a shared"
              + " (Redis/DB-backed) RateLimiter implementation to avoid per-replica abuse"
              + " multiplier.");
      this.counter = new InMemoryWindowCounter(Objects.requireNonNull(window, "window"));
    }

    @Override
    public int countAndIncrement(UserHandle user, String purpose, Instant now) {
      return counter.countAndIncrement(user + "|" + purpose);
    }

    /** Test helper to clear counters between cases. */
    public void reset() {
      counter.reset();
    }

    /** Exposed for diagnostics — tracks active counter keys. */
    public Set<String> keys() {
      return counter.keys();
    }
  }
}
