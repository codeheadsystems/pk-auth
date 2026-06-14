import { describe, expect, it } from "vitest";
import {RegistrationService} from "./registration";

describe("RegistrationService", () => {
  describe("start", () => {
    it("returns 403 when a username is not in the allowlist", async () => {
      const service = new RegistrationService("localhost", "alice")
      expect(
        () => service.start({ username: "eve", displayName: null, label: null, challenge: null }),
      ).toThrow("HTTP 403");
    });

    it("returns a StartRegistrationResponse when the request is valid", async () => {
      const service = new RegistrationService("localhost", "alice")

      const response = service.start({ username: "alice", displayName: null, label: null, challenge: null })

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
});
