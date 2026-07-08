
import * as b64u from "../../src/base64url";
import {
  FinishAuthenticationRequest,
  FinishAuthenticationResponse,
  FinishRegistrationRequest,
  FinishRegistrationResponse,
  StartAuthenticationRequest,
  StartAuthenticationResponse,
  StartRegistrationRequest,
  StartRegistrationResponse
} from "../../src";
import {HttpError} from "./httpServer";
import {Encoder} from "cbor-x";
import {WebAuthnType} from "./types";

interface PendingRegistrationEntry {
  displayName: string;
  username: string;
  userId: string;
  challenge: b64u.Base64Url;
  challengeId: string;
  rpId: string;
}

// PendingAuthenticationEntry tracks an authentication ceremony between start and finish. Unlike
// PendingRegistrationEntry, the username is optional: a caller may start authentication
// without knowing who is signing in yet (e.g. a resident/discoverable-credential flow), in
// which case the credential itself — looked up by id in `credentials` — is what identifies
// the user at finish time.
interface PendingAuthenticationEntry {
  challenge: b64u.Base64Url;
  challengeId: string;
  rpId: string;
  username: string | null;
}

// Credential is what finishRegistration persists so a later authentication ceremony can
// verify an assertion against it. Keyed by the base64url-encoded credential id.
interface Credential {
  publicKey: CryptoKey;
  userHandle: string;
  username: string;
  transports: string[];
  counter: number;
}

/*
CeremonyService is a server side service that can:
  - start registration
  - finish registration
  - start authentication
  - finish authentication
Instantiate the service with a relying party id [rpId] and a list of allowed users.
A registration is started with a call to startRegistration which will produce a challenge that
the client must respond to with a call to finishRegistration.
 */
export class CeremonyService {
  // pendingRegistrations is the map of registrations which have been started; but not yet
  // finished. Maps challenge id to a PendingRegistrationEntry structure.
  private readonly pendingRegistrations : Map<string, PendingRegistrationEntry>;
  // pendingAuthentications is the analogous map for authentication ceremonies:
  // challenge id -> PendingAuthenticationEntry.
  private readonly pendingAuthentications : Map<string, PendingAuthenticationEntry>;
  // credentials holds every credential that has completed registration, keyed by the
  // base64url-encoded credential id. This is what finishAuthentication verifies assertions
  // against — without it there would be no public key to check a signature with.
  private readonly credentials : Map<string, Credential>;

  private readonly rpId : string;
  private readonly allowedUsernames : string[];

  constructor(rpId: string,...allowedUsernames: string[]) {
    this.pendingRegistrations = new Map<string, PendingRegistrationEntry>();
    this.pendingAuthentications = new Map<string, PendingAuthenticationEntry>();
    this.credentials = new Map<string, Credential>();
    this.rpId = rpId;
    this.allowedUsernames = allowedUsernames ?? [];
  }

  async startRegistration(req : StartRegistrationRequest) : Promise<StartRegistrationResponse> {
    if (!this.allowedUsernames.includes(req.username)) {
      throw new HttpError(403, { error: `username '${req.username}' not allowed` });
    }
    const challengeId = b64u.encode(crypto.getRandomValues(new Uint8Array(16)));
    const challenge = b64u.encode(crypto.getRandomValues(new Uint8Array(32)));
    const userId = b64u.encode(crypto.getRandomValues(new Uint8Array(16)));
    const displayName = req.displayName ?? req.username;
    const pendingEntry = {
      displayName,
      username: req.username,
      userId,
      challenge,
      challengeId,
      rpId: this.rpId
    };

    // save the requests which will be validated in finish
    this.pendingRegistrations.set(challengeId, pendingEntry);
    return newStartRegistrationResponse(pendingEntry)
  }

  async finishRegistration(req: FinishRegistrationRequest): Promise<FinishRegistrationResponse> {
    const entry = this.pendingRegistrations.get(req.challengeId);
    if (!entry) {
      throw new HttpError(400, { error: `unknown challengeId: ${req.challengeId}` });
    }
    if (entry.username !== req.username) {
      throw new HttpError(400, { error: `username mismatch: ${req.username}` });
    }
    const clientData = parseClientData(req.response.response.clientDataJSON);
    if (clientData.type !== "webauthn.create") {
      throw new HttpError(400, { error: `wrong clientDataJSON type: ${clientData.type}` });
    }
    if (clientData.challenge !== entry.challenge) {
      throw new HttpError(400, { error: "challenge mismatch" });
    }

    const attestation = decodeAttestation(req.response.response.attestationObject)
    const publicKey = await parsePublicKey(attestation.publicKeyBytes)
    const isValid =  await verifySignature(
      publicKey,
      attestation.authData,
      attestation.signature,
      req.response.response.clientDataJSON);
    if (!isValid) {
      throw new HttpError(400, { error: "invalid signature" });
    }

    const credId = attestation.authData.slice(55, 55 + attestation.credentialIdLength);
    const base64CredId = b64u.encode(credId);
    const flags = attestation.authData[32]!;
    const transports = req.response.response.transports ?? [];
    const counter = attestation.dv.getUint32(33);

    this.pendingRegistrations.delete(req.challengeId);
    // Remember the credential so a later authentication ceremony has a public key to verify
    // an assertion against.
    this.credentials.set(base64CredId, {
      publicKey: publicKey,
      userHandle: entry.userId,
      username: entry.username,
      transports: transports,
      counter: counter,
    });
    return {
      credential: {
        credentialId: base64CredId,
        userHandle: entry.userId,
        label: req.label ?? "key",
        transports: transports,
        counter: counter,
        backupEligible: (flags & 0x08) !== 0,
        backupState: (flags & 0x10) !== 0,
        authenticatorData: b64u.encode(attestation.authData),
      },
    };
  }


  async startAuthentication(req: StartAuthenticationRequest): Promise<StartAuthenticationResponse> {
    if (req.username) {
      if (!this.isUserCredentialExist(req.username)) {
        throw new HttpError(403, { error: `username '${req.username}' not allowed` });
      }
    }

    const challengeId = b64u.encode(crypto.getRandomValues(new Uint8Array(16)));
    const challenge = b64u.encode(crypto.getRandomValues(new Uint8Array(32)));

    this.pendingAuthentications.set(challengeId, {
      challenge,
      challengeId,
      rpId: this.rpId,
      username: req.username ?? null,
    });

    return {
      challengeId,
      publicKey: {
        challenge,
        rpId: this.rpId,
        userVerification: "preferred",
      },
    };
  }

  async finishAuthentication(req: FinishAuthenticationRequest): Promise<FinishAuthenticationResponse> {
    const entry = this.pendingAuthentications.get(req.challengeId);
    if (!entry) {
      throw new HttpError(404, { error: `unknown challengeId: ${req.challengeId}` });
    }

    const clientData = parseClientData(req.response.response.clientDataJSON);
    if (clientData.type !== "webauthn.get") {
      throw new HttpError(400, { error: `wrong clientDataJSON type: ${clientData.type}` });
    }
    if (clientData.challenge !== entry.challenge) {
      throw new HttpError(400, { error: "challenge mismatch" });
    }

    // The credential id in the response — not the (optional) username from startAuth — is the
    // authority on who's signing in; this also covers resident-credential flows where the
    // username was never supplied to startAuthentication.
    const stored = this.credentials.get(req.response.rawId);
    if (!stored) {
      throw new HttpError(404, { error: `unknown credential: ${req.response.rawId}` });
    }
    if (entry.username && stored.username !== entry.username) {
      throw new HttpError(400, { error: `username mismatch: ${entry.username}` });
    }

    const authData = b64u.decode(req.response.response.authenticatorData);
    const signature = b64u.decode(req.response.response.signature);
    const isValid = await verifySignature(stored.publicKey, authData, signature, req.response.response.clientDataJSON);
    if (!isValid) {
      throw new HttpError(400, { error: "invalid signature" });
    }

    const flags = authData[32]!;
    if ((flags & 0x01) === 0) {
      throw new HttpError(400, { error: "user presence flag not set" });
    }

    const counter = new DataView(authData.buffer, authData.byteOffset).getUint32(33);
    // Clone/replay detection: a nonzero counter must strictly increase. Authenticators that
    // don't support counters (like this test suite's FakeAuthenticator) always report 0 —
    // per the WebAuthn spec that case is exempt from the check.
    if ((counter !== 0 || stored.counter !== 0) && counter <= stored.counter) {
      throw new HttpError(400, { error: "authenticator counter did not increase" });
    }
    stored.counter = counter;

    this.pendingAuthentications.delete(req.challengeId);

    return {
      token: b64u.encode(crypto.getRandomValues(new Uint8Array(32))),
    };
  }

  private isUserCredentialExist(username: string) : boolean {
    const credentials = [...this.credentials.entries()];
    const filtered = credentials.filter(([, cred]) => cred.username === username);
    return filtered.length > 0;
  }
}

// verifySignature checks a WebAuthn signature over authData || SHA-256(clientDataJSON) — the
// exact bytes both attestation (registration) and assertion (authentication) responses sign.
async function verifySignature(
  publicKey: CryptoKey,
  authData: Uint8Array<ArrayBufferLike>,
  signature: Uint8Array<ArrayBuffer>,
  clientDataJson: string,
) : Promise<boolean> {
  const data = b64u.decode(clientDataJson);
  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", data),
  );
  const verificationData = new Uint8Array(authData.length + clientDataHash.length);
  verificationData.set(authData);
  verificationData.set(clientDataHash, authData.length);

  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    signature,
    verificationData,
  );
}


function parsePublicKey(publicKeyBytes : Uint8Array<ArrayBuffer>) : Promise<CryptoKey> {
  try {
    return crypto.subtle.importKey(
      "raw",
      publicKeyBytes,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } catch(e) {
    const eMessage = e as {message: string}
    const message = eMessage && eMessage.message ? eMessage.message : "unknown error";
    throw new HttpError(400, { error: `invalid public key in authData: ${message}` });
  }
}

type Attestation = {
  dv: DataView,
  credentialIdLength: number,
  signature: Uint8Array<ArrayBuffer>,
  authData: Uint8Array<ArrayBufferLike>,
  publicKeyBytes: Uint8Array<ArrayBuffer>,
}

function decodeAttestation(attestation: string) : Attestation {
  const cbor = new Encoder({ useRecords: false, mapsAsObjects: false });
  const attestationObjectBytes = b64u.decode(attestation);
  const attObj = cbor.decode(attestationObjectBytes) as Map<string, unknown>;
  if (attObj.get("fmt") !== "packed") {
    throw new HttpError(400, { error: `unsupported attestation format: ${attObj.get("fmt")}` });
  }
  const authData = attObj.get("authData") as Uint8Array;
  const attStmt = attObj.get("attStmt") as Map<string, unknown>;
  const sig = attStmt.get("sig") as Uint8Array<ArrayBuffer>;

  // Extract COSE public key from authData
  const dv = new DataView(authData.buffer, authData.byteOffset);
  const credIdLen = dv.getUint16(53);
  const coseKey = cbor.decode(authData.slice(55 + credIdLen)) as Map<number, unknown>;
  const xBytes = coseKey.get(-2) as Uint8Array;
  const yBytes = coseKey.get(-3) as Uint8Array;

  const rawPoint = new Uint8Array(65);
  rawPoint[0] = 0x04;
  rawPoint.set(xBytes, 1);
  rawPoint.set(yBytes, 33);

  return {
    dv: dv,
    credentialIdLength: credIdLen,
    signature: sig,
    authData: authData,
    publicKeyBytes: rawPoint
  }
}

function parseClientData(clientDataJson: string) : { type: WebAuthnType, challenge: string } {
  // Decode and validate clientDataJSON
  const data = b64u.decode(clientDataJson);
  try {
    return JSON.parse(new TextDecoder().decode(data)) as {
      type: string;
      challenge: string;
    } as {type:WebAuthnType, challenge: string};
  } catch(e){
    const eMessage = e as {message: string}
    const message = eMessage && eMessage.message ? eMessage.message : "unknown error";
    throw new HttpError(400, { error: "invalid client data json: " + message });
  }
}

function newStartRegistrationResponse(pendingEntry: PendingRegistrationEntry) : StartRegistrationResponse {
  return {
    challengeId: pendingEntry.challengeId,
    publicKey: {
      rp: { id: pendingEntry.rpId, name: "Test" },
      user: {
        id: pendingEntry.userId,
        name: pendingEntry.username,
        displayName: pendingEntry.displayName,
      },
      challenge: pendingEntry.challenge,
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      timeout: 60_000,
      attestation: "direct",
    },
  };
}
