// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.demo.dropwizard;

import com.codeheadsystems.pkauth.config.CoseAlgorithm;
import com.codeheadsystems.pkauth.dropwizard.HasPkAuthConfig;
import com.codeheadsystems.pkauth.dropwizard.config.PkAuthConfig;
import io.dropwizard.core.Configuration;
import java.util.List;
import java.util.Set;

/**
 * Dropwizard {@link Configuration} for the demo. Hard-codes a working RP / JWT / alt-flow block so
 * the demo runs out of the box with {@code ./gradlew :examples:dropwizard-demo:run}. Production
 * deployments would bind these from a YAML file.
 */
public final class DemoConfiguration extends Configuration implements HasPkAuthConfig {

  private PkAuthConfig pkAuth =
      new PkAuthConfig(
          new PkAuthConfig.RelyingParty(
              "localhost", "pk-auth demo", Set.of("http://localhost:8080")),
          new PkAuthConfig.Jwt("https://issuer.local", "pkauth-demo", defaultDevSecret(), null),
          // Crypto-agility (ADR 0019): the COSE algorithm lists are explicit here for illustration.
          // These match the core defaults — `offered` is advertised to the authenticator,
          // `accepted`
          // is the (superset) verify allow-list. An operator can narrow either; the defaults are
          // the
          // historical union so no already-registered credential can fail verification.
          new PkAuthConfig.Ceremony(
              null,
              List.of(CoseAlgorithm.ES256, CoseAlgorithm.EdDSA, CoseAlgorithm.RS256),
              List.of(
                  CoseAlgorithm.ES256,
                  CoseAlgorithm.EdDSA,
                  CoseAlgorithm.RS256,
                  CoseAlgorithm.ES384,
                  CoseAlgorithm.RS384)),
          new PkAuthConfig.Otp(defaultDevOtpPepper()),
          new PkAuthConfig.MagicLink("http://localhost:8080"),
          new PkAuthConfig.BackupCode());

  @Override
  public PkAuthConfig pkAuth() {
    return pkAuth;
  }

  public void setPkAuth(PkAuthConfig pkAuth) {
    this.pkAuth = pkAuth;
  }

  /** 32-byte deterministic dev secret. Never use this in production. */
  static byte[] defaultDevSecret() {
    byte[] secret = new byte[32];
    for (int i = 0; i < secret.length; i++) {
      secret[i] = (byte) ((i * 17 + 3) & 0xff);
    }
    return secret;
  }

  /**
   * Deterministic dev OTP pepper. Production deploys must supply this via YAML / env-var and never
   * commit a value to source.
   */
  static byte[] defaultDevOtpPepper() {
    byte[] pepper = new byte[32];
    for (int i = 0; i < pepper.length; i++) {
      pepper[i] = (byte) ((i * 31 + 7) & 0xff);
    }
    return pepper;
  }
}
