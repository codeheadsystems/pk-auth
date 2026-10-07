// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.internal;

import com.codeheadsystems.pkauth.json.Base64Url;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.nio.charset.StandardCharsets;
import tools.jackson.databind.json.JsonMapper;

/**
 * Minimal {@code clientDataJSON} parser used to pull the {@code type}, {@code challenge}, and
 * {@code origin} fields out of a registration or assertion response before handing the rest off to
 * WebAuthn4J for full cryptographic verification.
 *
 * <p>This parser does not validate the contents; it exposes the fields pk-auth needs to look up the
 * {@code ChallengeRecord} in the store. All real validation (signature, RP id, origin allow-list,
 * counter, attestation) happens inside WebAuthn4J.
 */
public final class ClientDataJsonParser {

  private static final JsonMapper MAPPER =
      JsonMapper.builder()
          .changeDefaultPropertyInclusion(v -> v.withValueInclusion(JsonInclude.Include.NON_NULL))
          .build();

  private ClientDataJsonParser() {}

  public static ClientData parse(byte[] clientDataJsonBytes) {
    String json = new String(clientDataJsonBytes, StandardCharsets.UTF_8);
    return MAPPER.readValue(json, ClientData.class);
  }

  /** A subset of WebAuthn's {@code CollectedClientData}: only the fields pk-auth reads. */
  public record ClientData(String type, String challenge, String origin) {

    /** Decodes the base64url-encoded challenge into raw bytes. */
    public byte[] challengeBytes() {
      return Base64Url.decode(challenge);
    }
  }
}
