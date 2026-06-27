// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.otp;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.MessageFormatter;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import com.codeheadsystems.pkauth.spi.OtpRepository.StoredOtp;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Issues and verifies 6-digit numeric SMS OTPs for phone verification (brief §6.5). Defaults:
 * 5-minute TTL, max 5 verification attempts per code, rate limit 3 codes per (user, phone) per
 * 15-minute window.
 *
 * <p>OTP codes are hashed with {@code HMAC-SHA256(pepper, code)} rather than Argon2id. The 10^6
 * search space is small enough that Argon2id offers little additional protection, and the
 * per-attempt limit enforced by the repository is the primary brute-force defence. A server-side
 * pepper (never stored in the database) means a DB dump alone cannot enumerate codes; the attacker
 * also needs the pepper secret.
 *
 * <p>Construct via {@link #create(Dependencies, Config)} (or {@link #create(Dependencies, byte[])}
 * for the all-default case). Required collaborators (repository, sender, clock, formatter) live in
 * {@link Dependencies}; tunables (pepper, TTL, attempt caps, rate-limit) live in {@link Config}.
 */
public final class OtpService {

  /** Length of the OTP in digits. */
  public static final int OTP_LENGTH = 6;

  /** Default TTL for an issued OTP. */
  public static final Duration DEFAULT_TTL = Duration.ofMinutes(5);

  /** Default maximum verification attempts per OTP. */
  public static final int DEFAULT_MAX_ATTEMPTS = 5;

  /** Default rate limit: 3 codes per 15-minute window. */
  public static final int DEFAULT_RATE_LIMIT = 3;

  /** Default rate-limit window. */
  public static final Duration DEFAULT_RATE_WINDOW = Duration.ofMinutes(15);

  private static final String HMAC_ALGORITHM = "HmacSHA256";

  /** Result of a send attempt. */
  public sealed interface SendResult {
    /** OTP was generated and dispatched to the SMS sender. */
    record Sent(String otpId) implements SendResult {}

    /** Rate limit hit; the caller must wait before requesting another OTP. */
    record RateLimited(int countInWindow) implements SendResult {}
  }

  /** Result of a verify attempt. */
  public sealed interface VerifyResult {
    /** Code matched; the OTP record is consumed. */
    record Success() implements VerifyResult {}

    /** No active OTP for this (user, phone). */
    record NoActiveOtp() implements VerifyResult {}

    /** Code did not match the stored hash. */
    record CodeMismatch(int remainingAttempts) implements VerifyResult {}

    /** Too many failed attempts on this OTP. */
    record AttemptsExceeded() implements VerifyResult {}

    /** OTP existed but has expired. */
    record Expired() implements VerifyResult {}
  }

  private static final Logger LOG = LoggerFactory.getLogger(OtpService.class);

  private final OtpRepository repository;
  private final SmsSender smsSender;
  private final ClockProvider clockProvider;
  private final SecureRandom random;

  /**
   * Server-side pepper used as the HMAC key when hashing OTP codes. This value must never be stored
   * in the database — a DB dump alone cannot enumerate codes without it. The 10^6 search space is
   * manageable only if an attacker also possesses the pepper; combined with per-attempt limiting
   * this provides defence-in-depth.
   */
  private final byte[] pepper;

  private final Duration ttl;
  private final int maxAttempts;
  private final int rateLimit;
  private final Duration rateWindow;
  private final MessageFormatter<OtpContext, OtpMessage> messageFormatter;

  private OtpService(Dependencies deps, Config config) {
    this.repository = deps.repository();
    this.smsSender = deps.smsSender();
    this.clockProvider = deps.clockProvider();
    this.messageFormatter = deps.messageFormatter();
    this.random = config.random();
    this.pepper = Arrays.copyOf(config.pepper(), config.pepper().length);
    this.ttl = config.ttl();
    this.maxAttempts = config.maxAttempts();
    this.rateLimit = config.rateLimit();
    this.rateWindow = config.rateWindow();
  }

  /**
   * Canonical factory: required collaborators in {@link Dependencies}, tunables in {@link Config}.
   *
   * @since 0.9.1
   */
  public static OtpService create(Dependencies deps, Config config) {
    Objects.requireNonNull(deps, "deps");
    Objects.requireNonNull(config, "config");
    return new OtpService(deps, config);
  }

  /**
   * Convenience overload that builds a {@link Config} with all defaults and the supplied {@code
   * pepper}. The pepper has no sensible library default — hosts must supply a Base64-encoded ≥16
   * byte secret.
   *
   * @since 0.9.1
   */
  public static OtpService create(Dependencies deps, byte[] pepper) {
    Objects.requireNonNull(deps, "deps");
    return new OtpService(deps, Config.defaults(pepper));
  }

  /**
   * Generates a new OTP, persists it, and hands it to the {@link SmsSender}.
   *
   * @since 0.9.1
   */
  public SendResult startVerification(UserHandle user, String phoneE164) {
    Objects.requireNonNull(user, "user");
    Objects.requireNonNull(phoneE164, "phoneE164");

    Instant now = clockProvider.now();
    int recent = repository.countSince(user, phoneE164, now.minus(rateWindow));
    if (recent >= rateLimit) {
      LOG.info(
          "otp.send rate-limited user={} phone={} count={}", user, maskPhone(phoneE164), recent);
      return new SendResult.RateLimited(recent);
    }

    String code = newCode();
    String hash = hmacHash(code);

    String otpId = UUID.randomUUID().toString();
    repository.save(
        new StoredOtp(otpId, user, phoneE164, hash, 0, maxAttempts, false, now, now.plus(ttl)));
    OtpMessage message = messageFormatter.format(new OtpContext(user, phoneE164, code));
    smsSender.send(phoneE164, message.body());
    LOG.info("otp.send issued user={} phone={} otpId={}", user, maskPhone(phoneE164), otpId);
    return new SendResult.Sent(otpId);
  }

  /**
   * Verifies a candidate code against the most recent active OTP for (user, phone).
   *
   * @since 0.9.1
   */
  public VerifyResult finishVerification(UserHandle user, String phoneE164, String candidate) {
    Objects.requireNonNull(user, "user");
    Objects.requireNonNull(phoneE164, "phoneE164");
    Objects.requireNonNull(candidate, "candidate");

    Instant now = clockProvider.now();
    Optional<StoredOtp> activeOpt = repository.findLatestActive(user, phoneE164, now);
    if (activeOpt.isEmpty()) {
      // Run a throwaway HMAC so the no-active-OTP branch takes approximately the same wall-clock
      // time as the matching/mismatching branches below — the HMAC dominates the cost, so the
      // response can't leak (via timing) whether an OTP exists for (user, phone). Mirrors the
      // dummy-Argon2 verify in BackupCodeService.verify. The subsequent constant-time compare is
      // negligible by comparison and deliberately omitted here.
      hmacHash(candidate);
      return new VerifyResult.NoActiveOtp();
    }
    StoredOtp active = activeOpt.get();
    if (now.isAfter(active.expiresAt())) {
      return new VerifyResult.Expired();
    }

    // Increment first to close the TOCTOU window: the returned (1-based) count is authoritative.
    // The repo increments unconditionally, which closes the prior bypass where the guarded UPDATE
    // was a no-op once attempts == max_attempts. Reject with `>` (not `>=`) so the caller gets
    // exactly maxAttempts code comparisons: the submission whose post-increment count equals the
    // cap is still checked, and only the first submission *beyond* the cap is refused. Using `>=`
    // wasted the final attempt (only maxAttempts-1 codes were ever compared), contradicting the
    // documented "max N attempts" contract. An empty result means the row vanished between
    // findLatestActive and incrementAttempts (e.g. concurrent admin delete) — treat as a no-op
    // mismatch via NoActiveOtp so we don't pretend a phantom verify succeeded.
    OptionalInt incremented = repository.incrementAttempts(user, active.otpId());
    if (incremented.isEmpty()) {
      return new VerifyResult.NoActiveOtp();
    }
    int newAttempts = incremented.getAsInt();
    if (newAttempts > active.maxAttempts()) {
      return new VerifyResult.AttemptsExceeded();
    }

    String candidateHash = hmacHash(candidate);
    boolean matches =
        MessageDigest.isEqual(
            candidateHash.getBytes(StandardCharsets.UTF_8),
            active.hashedCode().getBytes(StandardCharsets.UTF_8));

    if (matches) {
      // consume() is guarded server-side; two concurrent verifies cannot both observe true.
      // The loser of the race sees false and is treated as a mismatch.
      boolean consumed = repository.consume(user, active.otpId());
      if (consumed) {
        LOG.info("otp.verify success user={} otpId={}", user, active.otpId());
        return new VerifyResult.Success();
      }
      LOG.info("otp.verify race-lost user={} otpId={}", user, active.otpId());
      int remaining = Math.max(0, active.maxAttempts() - newAttempts);
      return new VerifyResult.CodeMismatch(remaining);
    }
    int remaining = Math.max(0, active.maxAttempts() - newAttempts);
    LOG.info("otp.verify mismatch user={} otpId={} remaining={}", user, active.otpId(), remaining);
    return new VerifyResult.CodeMismatch(remaining);
  }

  private String newCode() {
    StringBuilder sb = new StringBuilder(OTP_LENGTH);
    for (int i = 0; i < OTP_LENGTH; i++) {
      sb.append(random.nextInt(10));
    }
    return sb.toString();
  }

  /**
   * Computes {@code HMAC-SHA256(pepper, code)} and returns it Base64-encoded.
   *
   * @param code plaintext code to hash
   * @return Base64 string suitable for storage and constant-time comparison
   */
  private String hmacHash(String code) {
    try {
      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(new SecretKeySpec(pepper, HMAC_ALGORITHM));
      byte[] digest = mac.doFinal(code.getBytes(StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(digest);
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new IllegalStateException("HMAC-SHA256 unavailable", e);
    }
  }

  /**
   * Masks a phone number for safe logging, keeping the first digit after {@code +} and the last 4
   * digits of the subscriber number.
   *
   * <p>Examples: {@code +15551234567} → {@code +1***4567}, {@code +441234567890} → {@code
   * +4***7890}. For inputs that are too short to mask meaningfully (fewer than 6 characters total),
   * or that are not recognisable as E.164 (e.g. {@code null}, no {@code +}), returns {@code +***}.
   *
   * @param phone E.164 phone number (expected to start with {@code +})
   * @return masked representation safe for log output
   */
  static String maskPhone(String phone) {
    // Need at least '+' + 1 country digit + at least 1 more digit + 4 suffix = 7 chars minimum
    // for a useful mask. Below that threshold, just return a fixed placeholder.
    if (phone == null
        || phone.length() < 7
        || phone.charAt(0) != '+'
        || !Character.isDigit(phone.charAt(1))) {
      return "+***";
    }
    // Keep the '+' and first digit of the country code only.
    String prefix = phone.substring(0, 2); // e.g. "+1", "+4", "+3"
    String suffix = phone.substring(phone.length() - 4); // last 4 digits
    return prefix + "***" + suffix;
  }

  /**
   * Canonical holder of the required collaborators for {@link OtpService}.
   *
   * <p>The {@code messageFormatter} renders the {@link OtpContext} (user, phone, generated code)
   * into an {@link OtpMessage} that is passed verbatim to {@link SmsSender#send(String, String)}.
   * Pass {@link DefaultOtpFormatter} to keep the historical hard-coded {@code "Your verification
   * code is XXXXXX"} body, or supply a host-specific formatter to brand or localize the SMS copy
   * without forking this service.
   *
   * @since 0.9.1
   */
  public record Dependencies(
      OtpRepository repository,
      SmsSender smsSender,
      ClockProvider clockProvider,
      MessageFormatter<OtpContext, OtpMessage> messageFormatter) {
    /** Compact constructor — enforces non-null on all required collaborators. */
    public Dependencies {
      Objects.requireNonNull(repository, "repository");
      Objects.requireNonNull(smsSender, "smsSender");
      Objects.requireNonNull(clockProvider, "clockProvider");
      Objects.requireNonNull(messageFormatter, "messageFormatter");
    }

    /**
     * Convenience factory that wires {@link DefaultOtpFormatter} as the message formatter — the
     * historical default body.
     *
     * @since 0.9.1
     */
    public static Dependencies of(
        OtpRepository repository, SmsSender smsSender, ClockProvider clockProvider) {
      return new Dependencies(repository, smsSender, clockProvider, new DefaultOtpFormatter());
    }
  }

  /**
   * Tunable configuration for {@link OtpService}.
   *
   * <p>The HMAC {@code pepper} is required (no library default) — hosts must supply a
   * Base64-encoded ≥16 byte secret. Every other field has a sensible default exposed via {@link
   * #defaults(byte[])}.
   *
   * @since 0.9.1
   */
  public record Config(
      SecureRandom random,
      byte[] pepper,
      Duration ttl,
      int maxAttempts,
      int rateLimit,
      Duration rateWindow) {
    /** Compact constructor — validates pepper length, field ranges, and non-null fields. */
    public Config {
      Objects.requireNonNull(random, "random");
      Objects.requireNonNull(pepper, "pepper");
      Objects.requireNonNull(ttl, "ttl");
      Objects.requireNonNull(rateWindow, "rateWindow");
      if (pepper.length < 16) {
        throw new IllegalArgumentException("pepper must be at least 16 bytes");
      }
      if (ttl.isZero() || ttl.isNegative()) {
        throw new IllegalArgumentException("ttl must be strictly positive");
      }
      if (rateWindow.isZero() || rateWindow.isNegative()) {
        throw new IllegalArgumentException("rateWindow must be strictly positive");
      }
      if (maxAttempts < 1) {
        throw new IllegalArgumentException("maxAttempts must be at least 1");
      }
      if (rateLimit < 1) {
        throw new IllegalArgumentException("rateLimit must be at least 1");
      }
    }

    /**
     * Returns a {@link Config} carrying the supplied pepper and the documented defaults for every
     * other field.
     *
     * @param pepper server-side HMAC key; must be at least 16 bytes
     * @since 0.9.1
     */
    public static Config defaults(byte[] pepper) {
      return new Config(
          new SecureRandom(),
          pepper,
          DEFAULT_TTL,
          DEFAULT_MAX_ATTEMPTS,
          DEFAULT_RATE_LIMIT,
          DEFAULT_RATE_WINDOW);
    }
  }
}
