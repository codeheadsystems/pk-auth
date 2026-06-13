// SPDX-License-Identifier: MIT

/**
 * Base64url (RFC 4648 §5) without padding — matches pk-auth's wire format.
 * The server's Jackson module emits unpadded base64url; browsers can mix
 * Uint8Array, ArrayBuffer, or already-base64url strings, so encode handles
 * all three.
 */

export type Base64Url = string;

export function encode(input: ArrayBuffer | Uint8Array | ArrayBufferView): Base64Url {
  const bytes = toUint8Array(input);
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    s += String.fromCharCode(bytes[i]!);
  }
  // base64url per RFC 4648 §5: map +/ to -_ and strip padding. Using replaceAll with
  // string literals (no regexes) keeps this linear — it avoids the ReDoS shape
  // SonarQube flags on `/=+$/`. `=` only ever appears as trailing base64 padding, so
  // removing all of it is equivalent to stripping the trailing run.
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export function decode(input: Base64Url): Uint8Array {
  const pad = "=".repeat((4 - (input.length % 4)) % 4);
  const normalized = input.replaceAll("-", "+").replaceAll("_", "/") + pad;
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function decodeToArrayBuffer(input: Base64Url): ArrayBuffer {
  const bytes = decode(input);
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
}

function toUint8Array(input: ArrayBuffer | Uint8Array | ArrayBufferView): Uint8Array {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
}
