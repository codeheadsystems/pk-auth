// SPDX-License-Identifier: MIT
import {Encoder} from "cbor-x";
import * as b64u from "../../src/base64url";
import {BufferUint8} from "./buffer";

type StoredCredential = { keyPair: CryptoKeyPair; rawId: Uint8Array };

export class FakeAuthenticator implements CredentialsContainer {
  // map id to keypair. The id is the base64 encoding of the randomly generated id [rawId].
  private readonly stored : Map<string, StoredCredential>;
  // lastId is used when get method is invoked w/o specifying a specific id.
  private lastId: string | null;

  constructor() {
    this.stored = new Map<string, StoredCredential>();
    this.lastId = null;
  }

  async create(options: CredentialCreationOptions): Promise<PublicKeyCredential> {
    const pk = options.publicKey;
    if (!pk) throw new Error("FakeAuthenticator.create: publicKey options are required");
    const rpId = pk.rp.id;
    if (!rpId) throw new Error("FakeAuthenticator.create: rp.id is required");

    const challenge = new Uint8Array(pk.challenge as ArrayBuffer);
    const clientDataBytes = encodeClientData(challenge, rpId, "webauthn.create");
    const keyPair = await ecdsa("P-256")
    const rawId = crypto.getRandomValues(new Uint8Array(16));
    const authData = await newAuthData(keyPair, rpId, rawId);
    const signature = await sign(authData, clientDataBytes, keyPair);
    const atoBytes = encodeAttestationObject(authData, signature);

    const id = b64u.encode(rawId);
    this.stored.set(id, { keyPair, rawId });
    this.lastId = id;

    return {
      rawId: rawId.buffer,
      id,
      type: "public-key",
      authenticatorAttachment: null,
      getClientExtensionResults: () => ({}),
      response: {
        clientDataJSON: newArrayBuffer(clientDataBytes),
        attestationObject: newArrayBuffer(atoBytes),
        getTransports: () => ["internal"],
      } as AuthenticatorAttestationResponse,
      toJSON: () => ({} as RegistrationResponseJSON),
    };
  }

  async get(options: CredentialRequestOptions): Promise<PublicKeyCredential | null> {
    const pk = options.publicKey;
    if (!pk) throw new Error("FakeAuthenticator.get: publicKey options are required");
    const rpId = pk.rpId;
    if (!rpId) throw new Error("FakeAuthenticator.get: rpId is required");

    const credential = this.findCredential(pk.allowCredentials);
    if (!credential) throw new Error("FakeAuthenticator.get: no matching credential found");

    const challenge = new Uint8Array(pk.challenge as ArrayBuffer);
    const clientDataBytes = encodeClientData(challenge, rpId, "webauthn.get");
    const authData = await assertionAuthData(rpId);
    const signature = await sign(authData, clientDataBytes, credential.keyPair);
    const { rawId } = credential;

    return {
      rawId: newArrayBuffer(rawId),
      id: b64u.encode(rawId),
      type: "public-key",
      authenticatorAttachment: null,
      getClientExtensionResults: () => ({}),
      response: {
        clientDataJSON: newArrayBuffer(clientDataBytes),
        authenticatorData: newArrayBuffer(authData),
        signature: newArrayBuffer(signature),
        userHandle: null,
      } as AuthenticatorAssertionResponse,
      toJSON: () => ({} as AuthenticationResponseJSON),
    };
  }

  private findCredential(
    allowCredentials: PublicKeyCredentialDescriptor[] | undefined,
  ): StoredCredential | undefined {
    if (allowCredentials && allowCredentials.length > 0) {
      for (const desc of allowCredentials) {
        const id = b64u.encode(new Uint8Array(desc.id as ArrayBuffer));
        const entry = this.stored.get(id);
        if (entry) return entry;
      }
      return undefined;
    }
    return this.lastId ? this.stored.get(this.lastId) : undefined;
  }

  async preventSilentAccess() { /*no impl*/ }

  async store() { /*no impl*/ }
}

function newArrayBuffer(buf: Uint8Array<ArrayBuffer> | Uint8Array<ArrayBufferLike>): ArrayBuffer {
  return buf.buffer.slice(
    buf.byteOffset,
    buf.byteOffset + buf.byteLength
  ) as ArrayBuffer
}

// sign authData || SHA-256(clientDataJSON)
async function sign(authData: Uint8Array, clientData: Uint8Array<ArrayBuffer>, keyPair: CryptoKeyPair): Promise<Uint8Array> {
  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", clientData),
  );
  const toSign = new BufferUint8().
  uint8array(authData).
  uint8array(clientDataHash).
  bytes();
  return new Uint8Array(
    await crypto.subtle.sign(
      {name: "ECDSA", hash: "SHA-256"},
      keyPair.privateKey,
      new Uint8Array(toSign),
    ),
  );
}

async function newAuthData(keyPair: CryptoKeyPair, rpId: string, id: Uint8Array): Promise<Uint8Array> {
  const coseKeyEncoded = await cose(keyPair.publicKey)
  const rpIdHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rpId)),
  );
  return new BufferUint8().
    uint8array(rpIdHash).
    uint8(0x45). // UP | UV | AT
    skip(4). // counter = 0
    skip(16). // AAGUID = all zeros
    uint16(id.length).
    uint8array(id).
    uint8array(coseKeyEncoded).
    bytes();
}

async function assertionAuthData(rpId: string): Promise<Uint8Array> {
  const rpIdHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rpId)),
  );
  return new BufferUint8()
    .uint8array(rpIdHash)
    .uint8(0x05) // UP | UV flags (no AT — assertion carries no attested credential data)
    .skip(4)     // counter = 0
    .bytes();
}

type Curve = "P-256" | "P-384" | "P-512"
function ecdsa(curve: Curve) : Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: curve },
    true,
    ["sign", "verify"],
  );
}

async function cose(publicKey : CryptoKey): Promise<Uint8Array> {
  const kty = 1
  const algorithm = 3;
  const curve = -1;
  const xCoord = -2;
  const yCoord = -3;

  const jwk = await crypto.subtle.exportKey("jwk", publicKey);
  const xBytes = b64u.decode(jwk.x!);
  const yBytes = b64u.decode(jwk.y!);
  const coseKey = new Map<number, unknown>([
    [kty, ktyValue(publicKey)],
    [algorithm, algorithmValue(publicKey)],
    [curve, curveValue(publicKey)],
    [xCoord, xBytes],
    [yCoord, yBytes],
  ]);
  const cbor = new Encoder({ useRecords: false, mapsAsObjects: false });
  return cbor.encode(coseKey);
}

function ktyValue(publicKey : CryptoKey) : number {
  const ktyECDSA = 2;
  if (publicKey.algorithm.name === "ECDSA") {
    return ktyECDSA;
  }
  throw new Error(`Unsupported key type: ${publicKey.algorithm.name}`)
}

function algorithmValue(publicKey : CryptoKey) : number {
  const algorithmES256 = -7;
  if (publicKey.algorithm.name === "ECDSA") {
    return algorithmES256;
  }
  throw new Error(`Unsupported algorithm: ${publicKey.algorithm.name}`)
}

function curveValue(publicKey : CryptoKey) : number {
  const curveP256 = -7;
  if (publicKey.algorithm.name === "ECDSA") {
    const { namedCurve } = publicKey.algorithm as EcKeyAlgorithm
    if (namedCurve === "P-256") {
      return curveP256;
    }
    throw new Error(`Unsupported curve: ${namedCurve}`)
  }
  throw new Error(`Unsupported algorithm: ${publicKey.algorithm.name}`)
}

type WebAuthnType = "webauthn.create" | "webauthn.get";

function encodeClientData(challenge: Uint8Array, rpId: string, webAuthnType: WebAuthnType): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(
    JSON.stringify({
      type: webAuthnType,
      challenge: b64u.encode(challenge),
      origin: `https://${rpId}`,
      crossOrigin: false,
    }),
  );
}

function encodeAttestationObject(authData: Uint8Array<ArrayBufferLike>, signature: Uint8Array<ArrayBufferLike>): Uint8Array {
  const cbor = new Encoder({ useRecords: false, mapsAsObjects: false });
  return cbor.encode({
    fmt: "packed",
    attStmt: { alg: -7, sig: signature },
    authData,
  });
}
