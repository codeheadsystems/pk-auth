// SPDX-License-Identifier: MIT
import { describe, expect, it } from "vitest";
import * as b64u from "../../src/base64url";
import { FakeAuthenticator } from "./fakeAuthenticator";
import { Encoder } from "cbor-x";

describe("FakeAuthenticator", () => {
  it("returns a credential whose clientDataJSON embeds the challenge and correct type", async () => {
    const auth = new FakeAuthenticator();
    const challenge = crypto.getRandomValues(new Uint8Array(32));

    const credentialCreateOptions = makeOptions("example.com", challenge);
    const credential = await auth.create(credentialCreateOptions);

    const clientData = decodeClientData(credential);
    expect(clientData.type).toBe("webauthn.create");
    expect(b64u.decode(clientData.challenge)).toEqual(challenge);
    expect(clientData.origin).toBe("https://example.com");
  });

  it("returns a packed attestation with a signature that verifies against the embedded public key", async () => {
    const auth = new FakeAuthenticator();
    const challenge = crypto.getRandomValues(new Uint8Array(32));

    const credential = await auth.create(makeOptions("example.com", challenge));

    const response = credential.response as AuthenticatorAttestationResponse;
    const attestation = await decodeAttestationData(response);
    expect(attestation.fmt).toBe("packed");
    const authData = attestation.authData;
    const verificationData = await toBeSigned(authData, response.clientDataJSON);
    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      attestation.publicKey,
      attestation.signature,
      verificationData,
    );
    expect(valid).toBe(true);
  });

  it("encodes rawId as base64url in the credential id field", async () => {
    const auth = new FakeAuthenticator();
    const credential = await auth.create(
      makeOptions("example.com", new Uint8Array(32)),
    );
    expect(credential.id).toBe(b64u.encode(credential.rawId));
  });
});

async function toBeSigned(authData: Uint8Array<ArrayBufferLike>, clientDataJSON: ArrayBuffer): Promise<Uint8Array<ArrayBuffer>> {
  const clientDataJSONBytes = new Uint8Array(clientDataJSON);
  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", clientDataJSONBytes),
  );
  const verificationData = new Uint8Array(authData.length + clientDataHash.length);
  verificationData.set(authData);
  verificationData.set(clientDataHash, authData.length);
  return verificationData;
}

interface AttestationData {
  fmt: string;
  statement: Map<string, unknown>;
  signature: Uint8Array<ArrayBuffer>;
  publicKey: CryptoKey;
  authData: Uint8Array;
}

async function decodeAttestationData(attestation: AuthenticatorAttestationResponse): Promise<AttestationData> {
  const cbor = new Encoder({ useRecords: false, mapsAsObjects: false });
  const attObj = cbor.decode(new Uint8Array(attestation.attestationObject)) as Map<string, unknown>;
  const authData = attObj.get("authData") as Uint8Array;
  const attStmt = attObj.get("attStmt") as Map<string, unknown>;
  const sig = attStmt.get("sig") as Uint8Array<ArrayBuffer>;

  // Extract COSE key from authData at offset 55 + credIdLen
  const view = new DataView(authData.buffer, authData.byteOffset);
  const credIdLen = view.getUint16(53);
  const coseKey = cbor.decode(authData.slice(55 + credIdLen)) as Map<number, unknown>;

  const xBytes = coseKey.get(-2) as Uint8Array;
  const yBytes = coseKey.get(-3) as Uint8Array;
  const rawPoint = new Uint8Array(65);
  rawPoint[0] = 0x04;
  rawPoint.set(xBytes, 1);
  rawPoint.set(yBytes, 33);

  const publicKey = await crypto.subtle.importKey(
    "raw",
    rawPoint,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );

  return {
    fmt: attObj.get("fmt") as string,
    statement: attStmt,
    signature: sig,
    publicKey: publicKey,
    authData: authData
  }
}

function makeOptions(rpId: string, challenge: Uint8Array): CredentialCreationOptions {
  return {
    publicKey: {
      rp: { id: rpId, name: "Test" },
      user: {
        id: new Uint8Array([1, 2, 3, 4]).buffer.slice(0, 4) as ArrayBuffer,
        name: "alice",
        displayName: "Alice",
      },
      challenge: challenge.buffer.slice(
        challenge.byteOffset,
        challenge.byteOffset + challenge.byteLength,
      ) as ArrayBuffer,
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    },
  };
}


interface ClientData  {
  type: string;
  challenge: string;
  origin: string
}

function decodeClientData(credential: PublicKeyCredential): ClientData {
  const response = credential.response as AuthenticatorAttestationResponse;
  return JSON.parse(
    new TextDecoder().decode(response.clientDataJSON),
  )
}
