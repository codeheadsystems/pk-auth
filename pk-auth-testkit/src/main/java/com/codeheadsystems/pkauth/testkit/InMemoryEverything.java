// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationServices;
import com.codeheadsystems.pkauth.config.CeremonyConfig;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.metrics.Metrics;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.webauthn4j.converter.util.ObjectConverter;

/**
 * Fully wired test harness: an {@link InMemoryCredentialRepository}, {@link InMemoryUserLookup},
 * {@link InMemoryChallengeStore}, a {@link FakeAuthenticator}, and a {@link
 * PasskeyAuthenticationService} built from them.
 *
 * <p>{@link #defaults()} constructs the brief's standard config, and {@link #builder()} gives
 * fine-grained control.
 */
public final class InMemoryEverything {

  public final InMemoryCredentialRepository credentials;
  public final InMemoryUserLookup users;
  public final InMemoryChallengeStore challenges;
  public final FakeAuthenticator authenticator;
  public final PasskeyAuthenticationService service;
  public final RelyingPartyConfig relyingParty;
  public final CeremonyConfig ceremonyConfig;

  private InMemoryEverything(Builder b) {
    this.relyingParty = b.relyingParty;
    this.ceremonyConfig = b.ceremonyConfig;
    this.credentials = new InMemoryCredentialRepository();
    this.users = new InMemoryUserLookup();
    this.challenges = new InMemoryChallengeStore();
    ObjectConverter objectConverter = new ObjectConverter();
    this.authenticator =
        FakeAuthenticator.builder()
            .origin(relyingParty.origins().iterator().next())
            .rpId(relyingParty.id())
            .objectConverter(objectConverter)
            .build();
    this.service =
        PasskeyAuthenticationServices.builder()
            .credentialRepository(credentials)
            .userLookup(users)
            .challengeStore(challenges)
            .relyingPartyConfig(relyingParty)
            .ceremonyConfig(ceremonyConfig)
            .clockProvider(b.clockProvider)
            .objectConverter(objectConverter)
            .metrics(Metrics.noop())
            .build();
  }

  /** Standard config from {@link PkAuthFixtures}. */
  public static InMemoryEverything defaults() {
    return builder().build();
  }

  /** Builder for custom relying-party / ceremony / clock configurations. */
  public static Builder builder() {
    return new Builder();
  }

  /** Builder for {@link InMemoryEverything}. */
  public static final class Builder {
    private RelyingPartyConfig relyingParty = PkAuthFixtures.defaultRelyingParty();
    private CeremonyConfig ceremonyConfig = PkAuthFixtures.defaultCeremonyConfig();
    private ClockProvider clockProvider = ClockProvider.system();

    private Builder() {}

    public Builder relyingParty(RelyingPartyConfig v) {
      this.relyingParty = v;
      return this;
    }

    public Builder ceremonyConfig(CeremonyConfig v) {
      this.ceremonyConfig = v;
      return this;
    }

    public Builder clockProvider(ClockProvider v) {
      this.clockProvider = v;
      return this;
    }

    public InMemoryEverything build() {
      return new InMemoryEverything(this);
    }
  }
}
