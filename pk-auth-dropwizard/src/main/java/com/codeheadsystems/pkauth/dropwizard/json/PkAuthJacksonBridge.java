// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.json;

import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;
import java.io.IOException;

/**
 * Teaches Dropwizard's Jackson 2 {@code ObjectMapper} to read and write the pk-auth wire types.
 * Dropwizard 5 still ships Jackson 2 (brief §6.11); pk-auth-core uses Jackson 3 (ADR 0009). The
 * bridge applies matched serialisers to Dropwizard's mapper rather than forking the entire JSON
 * contract, so payloads round-trip identically.
 *
 * <p>Specifically:
 *
 * <ul>
 *   <li>{@code byte[]} -> base64url string (no padding) and back.
 *   <li>{@link UserHandle} -> base64url string of its bytes.
 *   <li>{@link CredentialId} -> base64url string of its bytes.
 *   <li>{@link ChallengeId} -> its raw {@code value} string.
 * </ul>
 *
 * <p>The bridge does not touch Dropwizard's other Jackson modules (jdk8, java-time) because the
 * bundled Dropwizard mapper already wires those.
 */
public final class PkAuthJacksonBridge {

  private PkAuthJacksonBridge() {}

  /** Returns the pk-auth Jackson 2 module. */
  public static SimpleModule module() {
    SimpleModule m = new SimpleModule("pk-auth-dropwizard");
    m.addSerializer(byte[].class, new BytesSerializer());
    m.addDeserializer(byte[].class, new BytesDeserializer());
    m.addSerializer(UserHandle.class, new UserHandleSerializer());
    m.addDeserializer(UserHandle.class, new UserHandleDeserializer());
    m.addSerializer(CredentialId.class, new CredentialIdSerializer());
    m.addDeserializer(CredentialId.class, new CredentialIdDeserializer());
    m.addSerializer(ChallengeId.class, new ChallengeIdSerializer());
    m.addDeserializer(ChallengeId.class, new ChallengeIdDeserializer());
    return m;
  }

  /** Registers {@link #module()} on the supplied mapper. Idempotent. */
  public static ObjectMapper register(ObjectMapper mapper) {
    mapper.registerModule(module());
    return mapper;
  }

  private static final class BytesSerializer extends JsonSerializer<byte[]> {
    @Override
    public void serialize(byte[] value, JsonGenerator gen, SerializerProvider provider)
        throws IOException {
      gen.writeString(Base64Url.encode(value));
    }
  }

  private static final class BytesDeserializer extends JsonDeserializer<byte[]> {
    @Override
    public byte[] deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
      String s = p.getValueAsString();
      if (s == null) {
        return new byte[0];
      }
      return Base64Url.decode(s);
    }
  }

  private static final class UserHandleSerializer extends JsonSerializer<UserHandle> {
    @Override
    public void serialize(UserHandle value, JsonGenerator gen, SerializerProvider provider)
        throws IOException {
      gen.writeString(Base64Url.encode(value.value()));
    }
  }

  private static final class UserHandleDeserializer extends JsonDeserializer<UserHandle> {
    @Override
    public UserHandle deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
      return new UserHandle(Base64Url.decode(p.getValueAsString()));
    }
  }

  private static final class CredentialIdSerializer extends JsonSerializer<CredentialId> {
    @Override
    public void serialize(CredentialId value, JsonGenerator gen, SerializerProvider provider)
        throws IOException {
      gen.writeString(Base64Url.encode(value.value()));
    }
  }

  private static final class CredentialIdDeserializer extends JsonDeserializer<CredentialId> {
    @Override
    public CredentialId deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
      return new CredentialId(Base64Url.decode(p.getValueAsString()));
    }
  }

  private static final class ChallengeIdSerializer extends JsonSerializer<ChallengeId> {
    @Override
    public void serialize(ChallengeId value, JsonGenerator gen, SerializerProvider provider)
        throws IOException {
      gen.writeString(value.value());
    }
  }

  private static final class ChallengeIdDeserializer extends JsonDeserializer<ChallengeId> {
    @Override
    public ChallengeId deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
      return new ChallengeId(p.getValueAsString());
    }
  }
}
