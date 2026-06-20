import { describe, expect, it } from "vitest";
import { Encoder } from "cbor-x";
import * as b64u from "../../src/base64url";
import { decodeCreationOptions, encodeRegistrationResponse } from "../../src/ceremonies";
import { FakeAuthenticator } from "./fakeAuthenticator";
import { RegistrationService } from "./registration";

describe("RegistrationService", () => {
  describe("start a registration", () => {
    it("returns 403 when a username is not in the allowlist", async () => {
      const service = new RegistrationService("localhost", "alice");
      await expect(
        service.start({ username: "eve", displayName: null, label: null, challenge: null }),
      ).rejects.toThrow("HTTP 403");
    });

    it("returns a StartRegistrationResponse when the request is valid", async () => {
      const service = new RegistrationService("localhost", "alice")

      const response = await service.start({ username: "alice", displayName: null, label: null, challenge: null })

      expect(response.challengeId).toBeTypeOf("string");
      expect(response.publicKey.user.id).toBeTypeOf("string");
      expect(response.publicKey.challenge).toBeTypeOf("string");
      expect(response.publicKey.rp).toEqual({id: "localhost", name: "Test"});
      expect(response.publicKey.user.name).toEqual("alice");
      expect(response.publicKey.user.displayName).toEqual("alice");
      expect(response.publicKey.pubKeyCredParams).toEqual([{ type: "public-key", alg: -7 }]);
      expect(response.publicKey.timeout).toEqual(60_000);
      expect(response.publicKey.attestation).toEqual("direct");
    });
  });

  describe("finish a registration", () => {
    it("returns 400 for an unknown challengeId", async () => {
      const service = new RegistrationService("localhost", "alice");
      await expect(
        service.finish({
          challengeId: "does-not-exist",
          username: "alice",
          label: "key",
          response: {
            id: "x",
            rawId: "x",
            type: "public-key",
            response: { clientDataJSON: "x", attestationObject: "x", transports: [] },
          },
        }),
      ).rejects.toThrow("HTTP 400");
    });

    it("returns 400 for a username that does not match the started session", async () => {
      const service = new RegistrationService("localhost", "alice", "bob");
      const { challengeId, publicKey } = await service.start({ username: "alice", displayName: null, label: null, challenge: null });

      const auth = new FakeAuthenticator();
      const credential = await auth.create({ publicKey: decodeCreationOptions(publicKey) });
      const encoded = encodeRegistrationResponse(credential);

      await expect(
        service.finish({ challengeId, username: "bob", label: null, response: encoded }),
      ).rejects.toThrow("HTTP 400");
    });

    it("verifies the attestation and returns credential metadata", async () => {
      const service = new RegistrationService("localhost", "alice");
      const { challengeId, publicKey } = await service.start({ username: "alice", displayName: "Alice", label: null, challenge: null });

      const auth = new FakeAuthenticator();
      const credential = await auth.create({ publicKey: decodeCreationOptions(publicKey) });
      const encoded = encodeRegistrationResponse(credential);

      const { credential: cred } = await service.finish({ challengeId, username: "alice", label: "my-key", response: encoded });

      expect(cred.credentialId).toBeTypeOf("string");
      expect(cred.userHandle).toBeTypeOf("string");
      expect(cred.label).toBe("my-key");
      expect(cred.transports).toEqual(["internal"]);
      expect(cred.backupEligible).toBe(false);
      expect(cred.backupState).toBe(false);
    });

    it("returns 400 when the attestation signature is tampered", async () => {
      const service = new RegistrationService("localhost", "alice");
      const { challengeId, publicKey } = await service.start({ username: "alice", displayName: null, label: null, challenge: null });

      const auth = new FakeAuthenticator();
      const credential = await auth.create({ publicKey: decodeCreationOptions(publicKey) });
      const encoded = encodeRegistrationResponse(credential);

      // decode the attestation statement; modify it by flipping bits
      // then re-encode and submit to finish
      const cbor = new Encoder({ useRecords: false, mapsAsObjects: false });
      const attObjBytes = b64u.decode(encoded.response.attestationObject);
      const attObj = cbor.decode(attObjBytes) as Map<string, unknown>;
      const attStmt = attObj.get("attStmt") as Map<string, unknown>;
      const sig = attStmt.get("sig") as Uint8Array;
      sig[0]! ^= 0xff;
      const tampered = { ...encoded, response: { ...encoded.response, attestationObject: b64u.encode(cbor.encode(attObj) as Uint8Array) } };

      await expect(
        service.finish({ challengeId, username: "alice", label: null, response: tampered }),
      ).rejects.toThrow("HTTP 400");
    });

    it("returns 400 when the challenge in clientDataJSON belongs to a different session", async () => {
      const service = new RegistrationService("localhost", "alice");
      const s1 = await service.start({ username: "alice", displayName: null, label: null, challenge: null });
      const s2 = await service.start({ username: "alice", displayName: null, label: null, challenge: null });

      const auth = new FakeAuthenticator();
      const credential = await auth.create({ publicKey: decodeCreationOptions(s2.publicKey) });
      const encoded = encodeRegistrationResponse(credential);

      // finish using s1 challengeId but with s2's credential -- this should fail
      await expect(
        service.finish({ challengeId: s1.challengeId, username: "alice", label: null, response: encoded }),
      ).rejects.toThrow("HTTP 400");
    });
  });
});
