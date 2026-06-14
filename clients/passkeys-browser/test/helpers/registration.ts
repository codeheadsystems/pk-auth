
import * as b64u from "../../src/base64url";
import {StartRegistrationRequest, StartRegistrationResponse} from "../../src";
import {HttpError} from "./httpServer";

interface PendingEntry {
  displayName: string;
  username: string;
  userId: string;
  challenge: b64u.Base64Url;
  challengeId: string;
  rpId: string;
}

/*
RegistrationService is a representation of a server side service that can start and finish
client registrations.
Instantiate the service with a relying party id [rpId] and a list of allowed users.
A registration is started with a call to start which will produce a challenge that
the client must respond to when calling finish.
 */
export class RegistrationService {
  // pending is the map of registrations which have been started; but not yet finished.
  // Maps challenge id to a PendingEntry structure.
  // A registration.ts cannot be finished unless it has been successfully started.
  // A successfully started registration.ts must appear on the pending map.
  private readonly pending : Map<string, PendingEntry>;
  private readonly rpId : string;
  private readonly allowedUsernames : string[];

  constructor(rpId: string,...allowedUsernames: string[]) {
    this.pending = new Map<string, PendingEntry>();
    this.rpId = rpId;
    this.allowedUsernames = allowedUsernames ?? [];
  }

  start(req : StartRegistrationRequest) : StartRegistrationResponse {
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
      rpId: this.rpId };

    this.pending.set(challengeId, pendingEntry); // save the requests which will be validated in finish
    return newStartRegistrationResponse(pendingEntry)
  }
}

function newStartRegistrationResponse(pendingEntry: PendingEntry) : StartRegistrationResponse {
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
