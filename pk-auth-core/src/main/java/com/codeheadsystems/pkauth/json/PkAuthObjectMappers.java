// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.json;

import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.fasterxml.jackson.annotation.JsonInclude;
import tools.jackson.core.JsonGenerator;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueDeserializer;
import tools.jackson.databind.ValueSerializer;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.module.SimpleModule;

/**
 * Factory for the {@link ObjectMapper} pk-auth uses for every WebAuthn JSON payload. Jackson 3 is
 * used in the core (see ADR 0009); the surrounding annotations stay on the classical {@code
 * com.fasterxml.jackson.annotation} jar that ships with both Jackson 2 and 3.
 *
 * <p>Wire-format guarantees:
 *
 * <ul>
 *   <li>{@code byte[]} fields encode as base64url with no padding (RFC 4648 §5).
 *   <li>{@link UserHandle} and {@link CredentialId} encode as a base64url string of their bytes;
 *       {@link ChallengeId} encodes as its string value.
 *   <li>{@code java.time} types serialize as ISO-8601 strings, never as numeric timestamps.
 *   <li>Unknown properties on the wire fail deserialization (strict input).
 *   <li>Null properties are omitted on output.
 * </ul>
 *
 * <p>Jackson 3 mappers are immutable; each call returns a fresh builder so adapter modules may
 * apply additional configuration before {@code build()}.
 *
 * @since 0.9.0
 */
public final class PkAuthObjectMappers {

  private PkAuthObjectMappers() {}

  /** Returns a fully configured {@link JsonMapper}. */
  public static JsonMapper create() {
    return builder().build();
  }

  /** Returns the pre-configured builder so adapters can layer additional modules or settings. */
  public static JsonMapper.Builder builder() {
    // WRITE_DATES_AS_TIMESTAMPS defaults to false in Jackson 3, so no explicit disable is needed.
    return JsonMapper.builder()
        .addModule(pkAuthModule())
        .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
        .changeDefaultPropertyInclusion(
            value -> value.withValueInclusion(JsonInclude.Include.NON_NULL));
  }

  /**
   * Returns a fresh {@link SimpleModule} registering the byte[] / {@link UserHandle} / {@link
   * CredentialId} / {@link ChallengeId} (de)serializers used by pk-auth's wire contract. Adapter
   * modules that drive a host-framework {@link ObjectMapper} (Spring Boot 4 / Micronaut on Jackson
   * 3, etc.) register this module so their mapper produces the same wire shape the core's mapper
   * does.
   *
   * @since 0.9.1 {@link CredentialId} (de)serializer registered alongside {@link UserHandle} so
   *     adapters no longer need per-call-site {@code Base64Url.encode(...)} / {@code
   *     CredentialId.of(...)} stitching.
   */
  public static SimpleModule pkAuthModule() {
    SimpleModule module = new SimpleModule("pk-auth");
    module.addSerializer(byte[].class, new Base64UrlBytesSerializer());
    module.addDeserializer(byte[].class, new Base64UrlBytesDeserializer());
    module.addSerializer(UserHandle.class, new UserHandleSerializer());
    module.addDeserializer(UserHandle.class, new UserHandleDeserializer());
    module.addSerializer(CredentialId.class, new CredentialIdSerializer());
    module.addDeserializer(CredentialId.class, new CredentialIdDeserializer());
    module.addSerializer(ChallengeId.class, new ChallengeIdSerializer());
    module.addDeserializer(ChallengeId.class, new ChallengeIdDeserializer());
    return module;
  }

  private static final class Base64UrlBytesSerializer extends ValueSerializer<byte[]> {
    @Override
    public void serialize(byte[] value, JsonGenerator gen, SerializationContext ctxt) {
      gen.writeString(Base64Url.encode(value));
    }
  }

  private static final class Base64UrlBytesDeserializer extends ValueDeserializer<byte[]> {
    @Override
    public byte[] deserialize(JsonParser p, DeserializationContext ctxt) {
      String text = p.getValueAsString();
      if (text == null) {
        return new byte[0];
      }
      return Base64Url.decode(text);
    }
  }

  private static final class UserHandleSerializer extends ValueSerializer<UserHandle> {
    @Override
    public void serialize(UserHandle value, JsonGenerator gen, SerializationContext ctxt) {
      gen.writeString(Base64Url.encode(value.value()));
    }
  }

  private static final class UserHandleDeserializer extends ValueDeserializer<UserHandle> {
    @Override
    public UserHandle deserialize(JsonParser p, DeserializationContext ctxt) {
      return new UserHandle(Base64Url.decode(p.getValueAsString()));
    }
  }

  private static final class CredentialIdSerializer extends ValueSerializer<CredentialId> {
    @Override
    public void serialize(CredentialId value, JsonGenerator gen, SerializationContext ctxt) {
      gen.writeString(Base64Url.encode(value.value()));
    }
  }

  private static final class CredentialIdDeserializer extends ValueDeserializer<CredentialId> {
    @Override
    public CredentialId deserialize(JsonParser p, DeserializationContext ctxt) {
      return new CredentialId(Base64Url.decode(p.getValueAsString()));
    }
  }

  private static final class ChallengeIdSerializer extends ValueSerializer<ChallengeId> {
    @Override
    public void serialize(ChallengeId value, JsonGenerator gen, SerializationContext ctxt) {
      gen.writeString(value.value());
    }
  }

  private static final class ChallengeIdDeserializer extends ValueDeserializer<ChallengeId> {
    @Override
    public ChallengeId deserialize(JsonParser p, DeserializationContext ctxt) {
      return new ChallengeId(p.getValueAsString());
    }
  }
}
