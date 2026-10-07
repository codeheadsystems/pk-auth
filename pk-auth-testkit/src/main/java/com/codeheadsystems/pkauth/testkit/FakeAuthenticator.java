// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import com.codeheadsystems.pkauth.api.AuthenticationResponseJson;
import com.codeheadsystems.pkauth.api.AuthenticationResponseJson.AuthenticatorAssertionResponseJson;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson.AuthenticatorAttestationResponseJson;
import com.codeheadsystems.pkauth.api.StartAuthenticationResponse;
import com.codeheadsystems.pkauth.api.StartRegistrationResponse;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.jspecify.annotations.Nullable;
import tools.jackson.databind.json.JsonMapper;

/**
 * In-process WebAuthn authenticator for tests. Generates EC P-256 key pairs, builds valid
 * registration and assertion responses, and signs them so they round-trip through pk-auth's service
 * implementation without ever calling a real browser or hardware authenticator.
 *
 * <p>State is kept per-instance: each registration creates a new credential whose private key is
 * remembered for subsequent assertions. The authenticator increments its sign counter on each
 * assertion; tests that want to exercise counter-regression behaviour can set the counter
 * explicitly via {@link Builder#forceSignCount(long)}.
 */
public final class FakeAuthenticator {

  private static final byte FLAG_UP = (byte) 0x01;
  private static final byte FLAG_UV = (byte) 0x04;
  private static final byte FLAG_BE = (byte) 0x08;
  private static final byte FLAG_BS = (byte) 0x10;
  private static final byte FLAG_AT = (byte) 0x40;

  private final String origin;
  private final String rpId;
  private final AAGUID aaguid;
  private final byte flags;
  private final SecureRandom random;
  private final ObjectConverter objectConverter;
  private final AttestationObjectConverter attestationObjectConverter;
  private final AuthenticatorDataConverter authenticatorDataConverter;
  private final JsonMapper clientDataMapper;
  private final Map<String, Credential> credentialsById = new ConcurrentHashMap<>();
  private final @Nullable Long forceSignCountValue;

  private FakeAuthenticator(Builder b) {
    this.origin = b.origin;
    this.rpId = b.rpId;
    this.aaguid = b.aaguid;
    this.flags = b.flags;
    this.random = b.random == null ? new SecureRandom() : b.random;
    this.objectConverter = b.objectConverter == null ? new ObjectConverter() : b.objectConverter;
    this.attestationObjectConverter = new AttestationObjectConverter(this.objectConverter);
    this.authenticatorDataConverter = new AuthenticatorDataConverter(this.objectConverter);
    this.clientDataMapper =
        JsonMapper.builder()
            .changeDefaultPropertyInclusion(v -> v.withValueInclusion(JsonInclude.Include.NON_NULL))
            .build();
    this.forceSignCountValue = b.forceSignCount;
  }

  /** Builder with sensible defaults for the most common test scenarios. */
  public static Builder builder() {
    return new Builder();
  }

  // -- Registration ---------------------------------------------------------------------------

  /**
   * Produces a {@link RegistrationResponseJson} that finishes the supplied ceremony. A fresh EC
   * P-256 keypair is created and remembered against the credential id.
   */
  public RegistrationResponseJson createRegistrationResponse(StartRegistrationResponse start) {
    byte[] challenge = start.publicKey().challenge();
    byte[] clientDataJson = clientDataJson("webauthn.create", challenge);

    KeyPair keyPair = generateEcKeyPair();
    byte[] credentialId = new byte[32];
    random.nextBytes(credentialId);
    EC2COSEKey coseKey = EC2COSEKey.create(keyPair, COSEAlgorithmIdentifier.ES256);

    AttestedCredentialData acd = new AttestedCredentialData(aaguid, credentialId, coseKey);
    AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authData =
        new AuthenticatorData<>(rpIdHash(), flags, 0L, acd);

    AttestationObject attObj = new AttestationObject(authData, new NoneAttestationStatement());
    byte[] attestationObjectBytes = attestationObjectConverter.convertToBytes(attObj);

    credentialsById.put(
        Base64Url.encode(credentialId), new Credential(credentialId, keyPair, coseKey, 0L));

    return new RegistrationResponseJson(
        credentialId,
        credentialId,
        new AuthenticatorAttestationResponseJson(
            clientDataJson, attestationObjectBytes, List.of("internal"), null, null, null),
        null,
        null,
        "public-key");
  }

  // -- Assertion ------------------------------------------------------------------------------

  /**
   * Produces an {@link AuthenticationResponseJson} that finishes the supplied ceremony. Uses the
   * first credential matching {@code allowCredentials} (or the only stored credential when {@code
   * allowCredentials} is empty, i.e. usernameless flow).
   */
  public AuthenticationResponseJson createAssertionResponse(
      StartAuthenticationResponse start, UserHandle userHandle) {
    byte[] challenge = start.publicKey().challenge();
    byte[] clientDataJson = clientDataJson("webauthn.get", challenge);

    Credential cred = pickCredential(start);
    long signCount = forceSignCountValue == null ? cred.signCount + 1 : forceSignCountValue;
    cred.signCount = signCount;

    AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authData =
        new AuthenticatorData<>(
            rpIdHash(),
            (byte) (flags & ~FLAG_AT),
            signCount,
            new AuthenticationExtensionsAuthenticatorOutputs<>());
    byte[] authDataBytes = authenticatorDataConverter.convert(authData);

    byte[] signature = sign(cred.keyPair, authDataBytes, clientDataJson);

    return new AuthenticationResponseJson(
        cred.credentialId,
        cred.credentialId,
        new AuthenticatorAssertionResponseJson(
            clientDataJson, authDataBytes, signature, userHandle.value()),
        null,
        null,
        "public-key");
  }

  /** Looks up a registered credential by id, useful for assertions and assertions about state. */
  public @Nullable Credential credentialByIdHex(byte[] credentialId) {
    return credentialsById.get(Base64Url.encode(credentialId));
  }

  // -- Internals ------------------------------------------------------------------------------

  private byte[] clientDataJson(String type, byte[] challenge) {
    var node = clientDataMapper.createObjectNode();
    node.put("type", type);
    node.put("challenge", Base64Url.encode(challenge));
    node.put("origin", origin);
    node.put("crossOrigin", false);
    return clientDataMapper.writeValueAsString(node).getBytes(StandardCharsets.UTF_8);
  }

  private byte[] rpIdHash() {
    try {
      return MessageDigest.getInstance("SHA-256").digest(rpId.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  private static byte[] sign(KeyPair keyPair, byte[] authData, byte[] clientDataJson) {
    try {
      byte[] clientDataHash = MessageDigest.getInstance("SHA-256").digest(clientDataJson);
      ByteBuffer signed = ByteBuffer.allocate(authData.length + clientDataHash.length);
      signed.put(authData).put(clientDataHash);
      Signature sig = Signature.getInstance("SHA256withECDSA");
      sig.initSign(keyPair.getPrivate());
      sig.update(signed.array());
      return sig.sign();
    } catch (NoSuchAlgorithmException | SignatureException | java.security.InvalidKeyException e) {
      throw new IllegalStateException("ECDSA sign failed", e);
    }
  }

  private Credential pickCredential(StartAuthenticationResponse start) {
    // Privacy invariant (account-enumeration guard): allowCredentials is always non-null. An empty
    // list is
    // produced both by the usernameless flow and by unknown-username requests — we fall back to
    // the single-credential path in that case, exactly as a real authenticator would.
    var allow = start.publicKey().allowCredentials();
    for (var desc : allow) {
      Credential c = credentialsById.get(Base64Url.encode(desc.id()));
      if (c != null) {
        return c;
      }
    }
    if (credentialsById.size() == 1) {
      return credentialsById.values().iterator().next();
    }
    throw new IllegalStateException(
        "No registered credential matches the allowCredentials list: " + credentialsById.keySet());
  }

  private static KeyPair generateEcKeyPair() {
    try {
      KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
      g.initialize(new ECGenParameterSpec("secp256r1"));
      return g.generateKeyPair();
    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
      throw new IllegalStateException("Unable to generate EC keypair", e);
    }
  }

  /** Internal record of a registered credential: id, keypair, and the latest sign counter. */
  public static final class Credential {
    public final byte[] credentialId;
    public final KeyPair keyPair;
    public final EC2COSEKey coseKey;
    long signCount;

    Credential(byte[] credentialId, KeyPair keyPair, EC2COSEKey coseKey, long signCount) {
      this.credentialId = credentialId.clone();
      this.keyPair = keyPair;
      this.coseKey = coseKey;
      this.signCount = signCount;
    }

    public long signCount() {
      return signCount;
    }

    public String credentialIdHex() {
      return HexFormat.of().formatHex(credentialId);
    }
  }

  /** Builder for {@link FakeAuthenticator}. */
  public static final class Builder {
    private String origin = "https://example.com";
    private String rpId = "example.com";
    private AAGUID aaguid = new AAGUID(UUID.fromString("00000000-0000-0000-0000-000000000001"));
    private byte flags = (byte) (FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT);
    private @Nullable SecureRandom random;
    private @Nullable ObjectConverter objectConverter;
    private @Nullable Long forceSignCount;

    private Builder() {}

    public Builder origin(String v) {
      this.origin = v;
      return this;
    }

    public Builder rpId(String v) {
      this.rpId = v;
      return this;
    }

    public Builder aaguid(AAGUID v) {
      this.aaguid = v;
      return this;
    }

    public Builder withUserVerified(boolean v) {
      this.flags = v ? (byte) (this.flags | FLAG_UV) : (byte) (this.flags & ~FLAG_UV);
      return this;
    }

    public Builder withUserPresent(boolean v) {
      this.flags = v ? (byte) (this.flags | FLAG_UP) : (byte) (this.flags & ~FLAG_UP);
      return this;
    }

    public Builder secureRandom(SecureRandom v) {
      this.random = v;
      return this;
    }

    public Builder objectConverter(ObjectConverter v) {
      this.objectConverter = v;
      return this;
    }

    /** Pin assertions to return this exact sign count instead of incrementing. */
    public Builder forceSignCount(long v) {
      this.forceSignCount = v;
      return this;
    }

    public FakeAuthenticator build() {
      return new FakeAuthenticator(this);
    }
  }
}
