// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.backupcodes;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.ratelimit.InMemoryWindowCounter;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository.StoredBackupCode;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Issues, verifies, and rotates backup codes per brief §6.3.
 *
 * <p>Each generation produces N (default 10) cryptographically random 10-character alphanumeric
 * codes. Codes are returned to the caller exactly once at generation time; the service then stores
 * Argon2id hashes and never has access to the plaintext again. Verification matches a supplied code
 * against the user's stored hashes and consumes the matching record on success.
 *
 * <p>Verification is rate-limited via a {@link BackupCodeRateLimiter} (default: 5 attempts per user
 * per 60 seconds) to bound the CPU cost of the Argon2id work. Supply a custom {@link
 * BackupCodeRateLimiter} via the {@link Dependencies} record (or {@link Config}) to integrate with
 * a shared (Redis/DB-backed) store in multi-instance deployments.
 *
 * <p>Construct via {@link #create(Dependencies, Config)} (or {@link #create(Dependencies)} for the
 * all-default case).
 */
public final class BackupCodeService {

  /** Default count of codes generated per call. */
  public static final int DEFAULT_CODE_COUNT = 10;

  /**
   * Length of each plaintext code in characters. At length 10 over the 32-symbol {@link #ALPHABET}
   * each code carries ~50 bits of entropy (10 × log2(32)). This is <em>not</em> a quantum concern:
   * the real attack cost is dominated by the Argon2id verify hash plus the per-user verify rate
   * limiter ({@link #DEFAULT_RATE_LIMIT} attempts per {@link #DEFAULT_RATE_WINDOW}), not by brute
   * search of the code space. {@code CODE_LENGTH} is the lever if a deployment wants more margin;
   * the default is deliberately left unchanged.
   */
  public static final int CODE_LENGTH = 10;

  /** Default maximum verify attempts allowed per user within the rate-limit window. */
  public static final int DEFAULT_RATE_LIMIT = 5;

  /** Default window for the verify rate limit. */
  public static final Duration DEFAULT_RATE_WINDOW = Duration.ofSeconds(60);

  /** Default Argon2id iterations. */
  public static final int DEFAULT_ARGON2_ITERATIONS = 2;

  /** Default Argon2id memory cost (KiB). */
  public static final int DEFAULT_ARGON2_MEMORY = 65_536;

  /** Default Argon2id parallelism. */
  public static final int DEFAULT_ARGON2_PARALLELISM = 1;

  /**
   * A fixed throwaway Argon2id hash used for dummy verifications on consumed code slots so that
   * every loop iteration takes the same wall-clock time regardless of the slot's consumed state.
   * Pre-computed at class-load time with the same cost parameters as the production default
   * (iterations=2, memory=65536, parallelism=1).
   */
  private static final String DUMMY_HASH;

  static {
    Argon2 bootstrap = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
    DUMMY_HASH = bootstrap.hash(2, 65_536, 1, "dummy".toCharArray(), StandardCharsets.UTF_8);
  }

  private static final char[] ALPHABET =
      "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray(); // ambiguous chars omitted

  private static final Logger LOG = LoggerFactory.getLogger(BackupCodeService.class);

  private final BackupCodeRepository repository;
  private final ClockProvider clockProvider;
  private final BackupCodeRateLimiter rateLimiter;
  private final SecureRandom random;
  private final Argon2 argon2;
  private final int iterations;
  private final int memory;
  private final int parallelism;
  private final int codeCount;
  private final int rateLimit;

  /**
   * Pluggable rate limiter for {@link #verify} calls.
   *
   * <p>The default implementation ({@link InMemoryBackupCodeRateLimiter}) uses an in-process
   * counter that resets after {@link #DEFAULT_RATE_WINDOW}. Production multi-instance deployments
   * SHOULD override with a shared (Redis/DB-backed) implementation so rate limits are not
   * multiplied by the cluster size.
   */
  public interface BackupCodeRateLimiter {
    /**
     * Increments the verify attempt counter for the user and returns the new count.
     *
     * <p>Callers compare the returned count against the configured limit; if the count exceeds the
     * limit the verify attempt is rejected before any Argon2id work is done.
     *
     * @param user the user whose counter to increment
     * @param now the current wall-clock instant (supplied by the service, not re-fetched)
     * @return the new attempt count within the current window
     */
    int countAndIncrement(UserHandle user, Instant now);
  }

  /**
   * Result of a {@link #verify} call.
   *
   * <ul>
   *   <li>{@link Success} — the candidate matched an unconsumed code; the code is now consumed.
   *   <li>{@link NoMatch} — the candidate did not match any unconsumed code.
   *   <li>{@link RateLimited} — the user has exceeded the per-window verify limit; no Argon2id work
   *       was performed. Retry after {@link RateLimited#retryAfterSeconds()} seconds.
   * </ul>
   */
  public sealed interface VerifyResult {
    /** Candidate matched and was consumed. */
    record Success() implements VerifyResult {}

    /** Candidate did not match any unconsumed code. */
    record NoMatch() implements VerifyResult {}

    /**
     * Rate limit exceeded; no Argon2id work was done.
     *
     * @param retryAfterSeconds hint for callers/HTTP 429 Retry-After headers.
     */
    record RateLimited(int retryAfterSeconds) implements VerifyResult {}
  }

  private BackupCodeService(Dependencies deps, Config config) {
    this.repository = deps.repository();
    this.clockProvider = deps.clockProvider();
    this.rateLimiter = deps.rateLimiter();
    this.random = config.random();
    this.argon2 = config.argon2();
    this.iterations = config.iterations();
    this.memory = config.memory();
    this.parallelism = config.parallelism();
    this.codeCount = config.codeCount();
    this.rateLimit = config.rateLimit();
  }

  /**
   * Canonical factory: required collaborators in {@link Dependencies}, tunables in {@link Config}.
   *
   * @since 0.9.1
   */
  public static BackupCodeService create(Dependencies deps, Config config) {
    Objects.requireNonNull(deps, "deps");
    Objects.requireNonNull(config, "config");
    return new BackupCodeService(deps, config);
  }

  /**
   * Convenience overload that builds a {@link Config} with the documented defaults for every
   * tunable.
   *
   * @since 0.9.1
   */
  public static BackupCodeService create(Dependencies deps) {
    Objects.requireNonNull(deps, "deps");
    return new BackupCodeService(deps, Config.defaults());
  }

  /**
   * Generates a fresh set of {@code codeCount} backup codes. The plaintext list is returned to the
   * caller exactly once; the service persists only the hashes.
   */
  public List<String> generate(UserHandle user) {
    Objects.requireNonNull(user, "user");
    List<String> plaintext = new ArrayList<>(codeCount);
    List<StoredBackupCode> records = mintCodes(user, plaintext);
    for (StoredBackupCode record : records) {
      repository.save(record);
    }
    LOG.info("backup-codes.generate user={} count={}", user, codeCount);
    return List.copyOf(plaintext);
  }

  /**
   * Verifies a candidate plaintext code.
   *
   * <p>On match, the matching code is marked consumed and {@link VerifyResult.Success} is returned.
   * If the per-user rate limit is exceeded, {@link VerifyResult.RateLimited} is returned
   * immediately with no Argon2id work. Otherwise {@link VerifyResult.NoMatch} is returned.
   *
   * <p><strong>Constant-time guarantee:</strong> the method always iterates every stored code row
   * (both consumed and unconsumed). For consumed rows a dummy Argon2id verification is performed
   * against a fixed throwaway hash so that each loop iteration takes approximately the same
   * wall-clock time. This eliminates timing side-channels that would otherwise reveal the number of
   * unconsumed codes or the position of the matching slot.
   */
  public VerifyResult verify(UserHandle user, String candidate) {
    Objects.requireNonNull(user, "user");
    Objects.requireNonNull(candidate, "candidate");

    Instant now = clockProvider.now();
    int count = rateLimiter.countAndIncrement(user, now);
    if (count > rateLimit) {
      LOG.info("backup-codes.verify rate-limited user={} count={}", user, count);
      return new VerifyResult.RateLimited((int) DEFAULT_RATE_WINDOW.toSeconds());
    }

    List<StoredBackupCode> codes = repository.findByUserHandle(user);
    StoredBackupCode matchedCode = null;

    for (StoredBackupCode stored : codes) {
      char[] candidateChars = candidate.toCharArray();
      boolean matches;
      try {
        if (stored.consumed()) {
          // Dummy verify to keep iteration time constant regardless of consumed state.
          argon2.verify(DUMMY_HASH, candidateChars, StandardCharsets.UTF_8);
          matches = false;
        } else {
          matches = argon2.verify(stored.hashedCode(), candidateChars, StandardCharsets.UTF_8);
        }
      } finally {
        argon2.wipeArray(candidateChars);
      }
      // Track first match but do NOT return early — continue to preserve constant time.
      if (matches && matchedCode == null) {
        matchedCode = stored;
      }
    }

    if (matchedCode != null) {
      // The Argon2 verify above is racy with concurrent verifies of the same code: two
      // callers can both observe consumed=false and both pass Argon2 before either writes.
      // The repository.consume contract is the single point of truth — only the caller
      // whose guarded UPDATE / conditional write actually flipped the row from unconsumed
      // to consumed receives true. The loser of the race MUST be reported as a miss so
      // the recovery flow does not mint two JWTs from one code.
      boolean won = repository.consume(user, matchedCode.codeId(), now);
      if (won) {
        LOG.info(
            "backup-codes.verify outcome=success user={} codeId={}", user, matchedCode.codeId());
        return new VerifyResult.Success();
      }
      LOG.info(
          "backup-codes.verify outcome=miss reason=race-lost user={} codeId={}",
          user,
          matchedCode.codeId());
      return new VerifyResult.NoMatch();
    }

    LOG.info("backup-codes.verify outcome=miss user={}", user);
    return new VerifyResult.NoMatch();
  }

  /** Returns how many unconsumed codes the user still has. */
  public int remainingCount(UserHandle user) {
    return (int) repository.findByUserHandle(user).stream().filter(s -> !s.consumed()).count();
  }

  /**
   * Deletes every existing code for the user and issues a fresh set in a single atomic operation
   * via {@link BackupCodeRepository#replaceAll}. Named to align with {@code
   * AdminService.regenerateBackupCodes}.
   *
   * @since 0.9.1
   */
  public List<String> regenerateBackupCodes(UserHandle user) {
    Objects.requireNonNull(user, "user");
    List<String> plaintext = new ArrayList<>(codeCount);
    List<StoredBackupCode> records = mintCodes(user, plaintext);
    repository.replaceAll(user, records);
    LOG.info("backup-codes.regenerateBackupCodes user={} count={}", user, codeCount);
    return List.copyOf(plaintext);
  }

  /**
   * Mints {@link #codeCount} fresh codes for {@code user}, appending each plaintext code to {@code
   * plaintextSink} and returning the matching {@link StoredBackupCode} records (one per plaintext,
   * in the same order). Centralises the Argon2id hash + wipe pattern shared by {@link #generate}
   * and {@link #regenerateBackupCodes}.
   */
  private List<StoredBackupCode> mintCodes(UserHandle user, List<String> plaintextSink) {
    Instant now = clockProvider.now();
    List<StoredBackupCode> records = new ArrayList<>(codeCount);
    for (int i = 0; i < codeCount; i++) {
      String code = newCode();
      plaintextSink.add(code);
      char[] codeChars = code.toCharArray();
      String hash;
      try {
        hash = argon2.hash(iterations, memory, parallelism, codeChars, StandardCharsets.UTF_8);
      } finally {
        argon2.wipeArray(codeChars);
      }
      records.add(new StoredBackupCode(UUID.randomUUID().toString(), user, hash, false, now, null));
    }
    return records;
  }

  private String newCode() {
    StringBuilder sb = new StringBuilder(CODE_LENGTH);
    for (int i = 0; i < CODE_LENGTH; i++) {
      sb.append(ALPHABET[random.nextInt(ALPHABET.length)]);
    }
    return sb.toString();
  }

  /**
   * Canonical holder of the required collaborators for {@link BackupCodeService}.
   *
   * <p>The {@code rateLimiter} defaults to {@link InMemoryBackupCodeRateLimiter} when constructed
   * via {@link #of(BackupCodeRepository, ClockProvider)}; multi-instance deployments SHOULD supply
   * a shared (Redis/DB-backed) implementation directly to the canonical constructor.
   *
   * @since 0.9.1
   */
  public record Dependencies(
      BackupCodeRepository repository,
      ClockProvider clockProvider,
      BackupCodeRateLimiter rateLimiter) {
    /** Compact constructor — enforces non-null on all required collaborators. */
    public Dependencies {
      Objects.requireNonNull(repository, "repository");
      Objects.requireNonNull(clockProvider, "clockProvider");
      Objects.requireNonNull(rateLimiter, "rateLimiter");
    }

    /**
     * Convenience factory that wires {@link InMemoryBackupCodeRateLimiter} sized to {@link
     * #DEFAULT_RATE_WINDOW}. Suitable only for dev / single-instance deployments.
     *
     * @since 0.9.1
     */
    public static Dependencies of(BackupCodeRepository repository, ClockProvider clockProvider) {
      return new Dependencies(
          repository, clockProvider, new InMemoryBackupCodeRateLimiter(DEFAULT_RATE_WINDOW));
    }
  }

  /**
   * Tunable configuration for {@link BackupCodeService}.
   *
   * <p>Every field has a documented default exposed via {@link #defaults()}. Tests override the
   * Argon2id parameters and code count to keep wall-clock time low.
   *
   * @since 0.9.1
   */
  public record Config(
      SecureRandom random,
      Argon2 argon2,
      int iterations,
      int memory,
      int parallelism,
      int codeCount,
      int rateLimit) {
    /** Compact constructor — enforces non-null on object-typed fields and positive ranges. */
    public Config {
      Objects.requireNonNull(random, "random");
      Objects.requireNonNull(argon2, "argon2");
      if (iterations < 1) {
        throw new IllegalArgumentException("iterations must be at least 1");
      }
      if (memory < 1) {
        throw new IllegalArgumentException("memory must be at least 1");
      }
      if (parallelism < 1) {
        throw new IllegalArgumentException("parallelism must be at least 1");
      }
      if (codeCount < 1) {
        throw new IllegalArgumentException("codeCount must be at least 1");
      }
      if (rateLimit < 1) {
        throw new IllegalArgumentException("rateLimit must be at least 1");
      }
    }

    /**
     * Returns a {@link Config} with the documented production defaults for every field. Fresh
     * {@link SecureRandom} and {@link Argon2} instances are created.
     *
     * @since 0.9.1
     */
    public static Config defaults() {
      return new Config(
          new SecureRandom(),
          Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id),
          DEFAULT_ARGON2_ITERATIONS,
          DEFAULT_ARGON2_MEMORY,
          DEFAULT_ARGON2_PARALLELISM,
          DEFAULT_CODE_COUNT,
          DEFAULT_RATE_LIMIT);
    }
  }

  /**
   * Simple in-process rate limiter backed by {@link InMemoryWindowCounter}.
   *
   * <p><strong>FOR DEV / SINGLE-INSTANCE USE ONLY.</strong> Production multi-instance deployments
   * MUST replace this with a shared (Redis/DB-backed) {@link BackupCodeRateLimiter} implementation;
   * otherwise the per-replica limit multiplies by the cluster size.
   *
   * @since 0.9.1
   */
  public static final class InMemoryBackupCodeRateLimiter implements BackupCodeRateLimiter {

    private static final Logger RL_LOG =
        LoggerFactory.getLogger(InMemoryBackupCodeRateLimiter.class);

    private final InMemoryWindowCounter counter;

    public InMemoryBackupCodeRateLimiter(Duration window) {
      this.counter = new InMemoryWindowCounter(Objects.requireNonNull(window, "window"));
      RL_LOG.info(
          "backup-codes.rate-limiter InMemoryBackupCodeRateLimiter instantiated — FOR DEV /"
              + " SINGLE-INSTANCE USE ONLY. Production deployments MUST replace this with a"
              + " shared (Redis/DB-backed) BackupCodeRateLimiter.");
    }

    @Override
    public int countAndIncrement(UserHandle user, Instant now) {
      return counter.countAndIncrement(user.toString());
    }

    /** Test helper: clears all counters. */
    public void reset() {
      counter.reset();
    }
  }
}
