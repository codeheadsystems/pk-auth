// SPDX-License-Identifier: MIT
import { describe, expect, it, vi } from "vitest";
import * as b64u from "../src/base64url";
import {
  PkAuthCeremonyClient,
  decodeCreationOptions,
  decodeRequestOptions,
  encodeAuthenticationResponse,
  encodeRegistrationResponse,
} from "../src/ceremonies";
import type {
  FinishRegistrationRequest, FinishRegistrationResponse,
  PublicKeyCredentialCreationOptionsJson,
  PublicKeyCredentialRequestOptionsJson, StartRegistrationRequest, StartRegistrationResponse,
} from "../src/types";
import {
  decodeJson,
  encodeJson,
  Handler,
  HttpError,
  HttpHandler,
  HttpServer,
  newHttpHandler
} from "./helpers/httpServer";
import * as http from "node:http";
import {CeremonyService} from "./helpers/ceremony";
import {FakeAuthenticator} from "./helpers/fakeAuthenticator";
import {
  FinishAuthenticationRequest,
  FinishAuthenticationResponse,
  StartAuthenticationRequest,
  StartAuthenticationResponse
} from "../dist/src";

const CREATE_OPTIONS_JSON: PublicKeyCredentialCreationOptionsJson = {
  rp: { id: "example.com", name: "Example" },
  user: {
    id: b64u.encode(new Uint8Array([1, 2, 3, 4])),
    name: "alice",
    displayName: "Alice",
  },
  challenge: b64u.encode(new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd])),
  pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  timeout: 60_000,
  attestation: "none",
};

const REQUEST_OPTIONS_JSON: PublicKeyCredentialRequestOptionsJson = {
  challenge: b64u.encode(new Uint8Array([1, 1, 1, 1])),
  rpId: "example.com",
  userVerification: "preferred",
  allowCredentials: [
    {
      id: b64u.encode(new Uint8Array([9, 8, 7])),
      type: "public-key",
      transports: ["internal"],
    },
  ],
};

function fakeCredential(rawId: Uint8Array, response: AuthenticatorResponse): PublicKeyCredential {
  return {
    rawId: rawId.buffer.slice(rawId.byteOffset, rawId.byteOffset + rawId.byteLength) as ArrayBuffer,
    id: b64u.encode(rawId),
    type: "public-key",
    authenticatorAttachment: null,
    getClientExtensionResults: () => ({}),
    response,
    toJSON: () => ({}),
  } as unknown as PublicKeyCredential;
}

describe("decodeCreationOptions", () => {
  it("base64url-decodes challenge and user.id", () => {
    const decoded = decodeCreationOptions(CREATE_OPTIONS_JSON);
    expect(new Uint8Array(decoded.challenge as ArrayBuffer)).toEqual(
      new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]),
    );
    expect(new Uint8Array(decoded.user.id as ArrayBuffer)).toEqual(
      new Uint8Array([1, 2, 3, 4]),
    );
    expect(decoded.rp).toEqual({ id: "example.com", name: "Example" });
    expect(decoded.attestation).toBe("none");
  });
});

describe("decodeRequestOptions", () => {
  it("base64url-decodes challenge and allowCredentials ids", () => {
    const decoded = decodeRequestOptions(REQUEST_OPTIONS_JSON);
    expect(new Uint8Array(decoded.challenge as ArrayBuffer)).toEqual(
      new Uint8Array([1, 1, 1, 1]),
    );
    const ac = decoded.allowCredentials![0]!;
    expect(new Uint8Array(ac.id as ArrayBuffer)).toEqual(new Uint8Array([9, 8, 7]));
  });
});

describe("encodeRegistrationResponse", () => {
  it("encodes attestation + clientDataJSON + transports", () => {
    const rawId = new Uint8Array([5, 6, 7]);
    const clientData = new Uint8Array([0x7b]); // "{"
    const attestation = new Uint8Array([0xa0]);
    const credential = fakeCredential(rawId, {
      clientDataJSON: clientData.buffer as ArrayBuffer,
      attestationObject: attestation.buffer as ArrayBuffer,
      getTransports: () => ["internal", "hybrid"],
    } as unknown as AuthenticatorResponse);
    const encoded = encodeRegistrationResponse(credential);
    expect(encoded.id).toBe(b64u.encode(rawId));
    expect(encoded.rawId).toBe(b64u.encode(rawId));
    expect(encoded.type).toBe("public-key");
    expect(encoded.response.clientDataJSON).toBe(b64u.encode(clientData));
    expect(encoded.response.attestationObject).toBe(b64u.encode(attestation));
    expect(encoded.response.transports).toEqual(["internal", "hybrid"]);
  });

  it("falls back to empty transports when getTransports is absent", () => {
    const rawId = new Uint8Array([1]);
    const credential = fakeCredential(rawId, {
      clientDataJSON: new Uint8Array([0]).buffer as ArrayBuffer,
      attestationObject: new Uint8Array([0]).buffer as ArrayBuffer,
    } as unknown as AuthenticatorResponse);
    const encoded = encodeRegistrationResponse(credential);
    expect(encoded.response.transports).toEqual([]);
  });
});

describe("encodeAuthenticationResponse", () => {
  it("encodes assertion response and a null userHandle", () => {
    const rawId = new Uint8Array([2]);
    const credential = fakeCredential(rawId, {
      clientDataJSON: new Uint8Array([0x7b]).buffer as ArrayBuffer,
      authenticatorData: new Uint8Array([0x55]).buffer as ArrayBuffer,
      signature: new Uint8Array([0x99]).buffer as ArrayBuffer,
      userHandle: null,
    } as unknown as AuthenticatorResponse);
    const encoded = encodeAuthenticationResponse(credential);
    expect(encoded.response.userHandle).toBeNull();
    expect(encoded.response.signature).toBe(b64u.encode(new Uint8Array([0x99])));
  });

  it("encodes a present userHandle", () => {
    const handle = new Uint8Array([0xab, 0xcd]);
    const credential = fakeCredential(new Uint8Array([3]), {
      clientDataJSON: new Uint8Array([0]).buffer as ArrayBuffer,
      authenticatorData: new Uint8Array([0]).buffer as ArrayBuffer,
      signature: new Uint8Array([0]).buffer as ArrayBuffer,
      userHandle: handle.buffer as ArrayBuffer,
    } as unknown as AuthenticatorResponse);
    expect(encodeAuthenticationResponse(credential).response.userHandle).toBe(b64u.encode(handle));
  });
});

describe("PkAuthCeremonyClient http test", () => {
  it("when startRegistration endpoint returns 500 then the client makes no attempt to create credential", async() => {
    using server= await startHttpServer({
      [registrationStartPath]: errorHttpHandler,
    });
    const credentialsContainer = noOpCredentialsContainer();
    const client = new PkAuthCeremonyClient(
      { apiBase: server.url },
      { credentials: credentialsContainer },
    );

    await expect(client.register({ username: "alice", label: "key" })).rejects.toThrow("HTTP 500: unit test error from errorHttpHandler");

    expect(credentialsContainer.create).not.toHaveBeenCalled(); // this proves the client did not attempt to create a credential upon failure to start ceremony.ts
  })

  it("when start registration succeeds but no credential is created, then the client fails with credential cancellation", async() => {
    const registration = new CeremonyService("localhost", "alice", "bob")
    using server= await startHttpServer({
      [registrationStartPath]: newStartHandler(registration),
      [registrationFinishPath]: newFinishHandler(registration)
    });
    const credentialsContainer = noOpCredentialsContainer();
    const client = new PkAuthCeremonyClient(
      { apiBase: server.url },
      { credentials: credentialsContainer },
    );

    await expect(client.register({ username: "alice", label: "key" })).rejects.toThrow(/creation was cancelled/);
    expect(credentialsContainer.create).toHaveBeenCalled(); // this proves the client did attempt to create a credential
  })

  it("when finish registration fails, the credential was still created", async() => {
    const registration = new CeremonyService("localhost", "alice", "bob")
    using server= await startHttpServer({
      [registrationStartPath]: newStartHandler(registration),
      [registrationFinishPath]: errorHttpHandler
    });
    const credentialsContainer = new FakeAuthenticator();
    credentialsContainer.create = vi.fn(credentialsContainer.create)
    const client = new PkAuthCeremonyClient(
      { apiBase: server.url },
      { credentials: credentialsContainer },
    );

    await expect(client.register({ username: "alice", label: "key" })).rejects.toThrow("HTTP 500: unit test error from errorHttpHandler");

    expect(credentialsContainer.create).toHaveBeenCalled(); // this proves the client did attempt to create a credential
  })

  it("when registering a credential, then the server returns a finished response", async() => {
    const registration = new CeremonyService("localhost", "alice", "bob")
    using server = await startHttpServer({
      [registrationStartPath]: newStartHandler(registration),
      [registrationFinishPath]: newFinishHandler(registration)
    });
    const authenticator = new FakeAuthenticator();
    const client = new PkAuthCeremonyClient(
      { apiBase: server.url },
      { credentials: authenticator },
    );

    const response = await client.register({ username: "alice", label: "key" });
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const credentialRequestOptions = {
      publicKey: {
        challenge: challenge,
        rpId: "localhost"
      }
    }
    const retrievedCredential = await authenticator.get(credentialRequestOptions);

    expect(response.credential.label).to.equal("key");
    expect(response.credential.credentialId).not.toBe("");
    expect(response.credential.userHandle).not.toBe("");
    expect(response.credential.authenticatorData).not.toBe("");
    expect(retrievedCredential?.id).toEqual(response.credential.credentialId);
    expect(retrievedCredential?.type).toEqual("public-key");
  })

  it("when registering a credential, it can be used for authentication", async () => {
    const server = await testServer("alice", "bob");
    const authenticator = new FakeAuthenticator();
    const client = new PkAuthCeremonyClient(
      { apiBase: server.url },
      { credentials: authenticator },
    );

    await client.register({ username: "alice", label: "key" });
    const authenticated = await client.authenticate({ username: "alice"})

    expect(authenticated.token).to.match(/\S+/); //at least one non-whitespace char
  });

  it("when failing to authenticate on start, the client fails gracefully", async () => {
    const server = await testServer("alice");
    const authenticator = new FakeAuthenticator();
    const client = new PkAuthCeremonyClient(
      { apiBase: server.url },
      { credentials: authenticator },
    );

    await client.register({ username: "alice", label: "key" });

    await expect(client.authenticate({ username: "not_alice"})).rejects.toThrow('HTTP 403: {"error":"username \'not_alice\' not allowed"}');
  });

  it("when authenticating, omit username supports any user that can respond to challenge to be authenticated", async () => {
    const server = await testServer("alice");
    const authenticator = new FakeAuthenticator();
    const client = new PkAuthCeremonyClient(
      { apiBase: server.url },
      { credentials: authenticator },
    );

    await client.register({ username: "alice", label: "key" });
    const authenticated = await client.authenticate({ }) // no username means any user

    expect(authenticated.token).to.match(/\S+/); //at least one non-whitespace char
  });

  it("when authenticating, conditional mediation is honored by client", async () => {
    const server = await testServer("alice");
    const authenticator = new FakeAuthenticator({requireConditionalMediationOnGet: true});
    const client = new PkAuthCeremonyClient(
      { apiBase: server.url },
      { credentials: authenticator },
    );

    await client.register({ username: "alice", label: "key" });
    const authenticated = await client.authenticate({ conditional: true})

    expect(authenticated.token).to.match(/\S+/); //at least one non-whitespace char
  });

  it("when authenticating, then failure to get a credential results in authentication cancelled", async () => {
    const server = await testServer("alice", "bob");
    const authenticator = new FakeAuthenticatorThatFailsGet();
    const client = new PkAuthCeremonyClient(
      { apiBase: server.url },
      { credentials: authenticator },
    );

    await client.register({ username: "alice", label: "key" });
    await expect(client.authenticate({ username: "alice"})).rejects.toThrow("pk-auth: authentication was cancelled");
  });

  const registrationStartPath = "/auth/passkeys/registration/start";
  const registrationFinishPath = "/auth/passkeys/registration/finish";
  const authenticationStartPath = "/auth/passkeys/authentication/start";
  const authenticationFinishPath = "/auth/passkeys/authentication/finish";

  async function testServer(...allowedUsernames: string[]) : Promise<HttpServer> {
    const registration = new CeremonyService("localhost", ...allowedUsernames)
    return startHttpServer({
      [registrationStartPath]: newStartHandler(registration),
      [registrationFinishPath]: newFinishHandler(registration),
      [authenticationStartPath]: newAuthenticationStartHandler(registration),
      [authenticationFinishPath]: newAuthenticationFinishHandler(registration)
    });
  }

  function noOpCredentialsContainer() : CredentialsContainer {
    return { create: vi.fn(), get: vi.fn(), preventSilentAccess: vi.fn(), store: vi.fn()};
  }

  function errorHttpHandler(_: http.IncomingMessage, res: http.ServerResponse) : void {
    res.writeHead(500)
    res.end("unit test error from errorHttpHandler")
  }

  function newStartHandler(registration: CeremonyService) : HttpHandler{
    const endpoint = async (req: StartRegistrationRequest) : Promise<StartRegistrationResponse> => {
      return registration.startRegistration(req);
    };
    const handler = new Handler(decodePost, endpoint, encodeJson);
    return newHttpHandler(handler);
  }

  function newAuthenticationStartHandler(registration: CeremonyService) : HttpHandler {
    const endpoint = async (req: StartAuthenticationRequest) : Promise<StartAuthenticationResponse> => {
      return registration.startAuthentication(req);
    };
    const handler = new Handler(decodePost, endpoint, encodeJson);
    return newHttpHandler(handler);
  }

  function newAuthenticationFinishHandler(registration: CeremonyService) : HttpHandler {
    const endpoint = async (req: FinishAuthenticationRequest) : Promise<FinishAuthenticationResponse> => {
      return registration.finishAuthentication(req);
    };
    const handler = new Handler(decodePost, endpoint, encodeJson);
    return newHttpHandler(handler);
  }

  function newFinishHandler(registration: CeremonyService) : HttpHandler{
    const endpoint = async (req: FinishRegistrationRequest) : Promise<FinishRegistrationResponse> => {
      return registration.finishRegistration(req);
    };
    const handler = new Handler(decodePost, endpoint, encodeJson);
    return newHttpHandler(handler);
  }

  async function decodePost<T>(req : http.IncomingMessage): Promise<T> {
      if (req.method !== "POST") {
        throw new HttpError(405, `method '${req.method}' not allowed`);
      }
      return decodeJson(req);
  }

  async function startHttpServer(routes: Record<string, HttpHandler>) : Promise<HttpServer> {
    const server = new HttpServer(routes);
    await server.listen();
    return server
  }
});

describe("PkAuthCeremonyClient.register (start-body contract)", () => {
  it("passes an explicit displayName and label straight through", async () => {
    const { fetchImpl, bodies } = ceremonyFetch({
      "/registration/start": { challengeId: "ch-1", publicKey: CREATE_OPTIONS_JSON },
      "/registration/finish": { credential: { credentialId: "cred" } },
    });
    const client = new PkAuthCeremonyClient(
      { apiBase: "https://x", fetch: fetchImpl as unknown as typeof fetch },
      { credentials: new FakeAuthenticator() },
    );
    await client.register({ username: "bob", displayName: "Bobby", label: "yubikey" });
    expect(bodies["/registration/start"]).toMatchObject({ displayName: "Bobby", label: "yubikey" });
    expect(bodies["/registration/finish"]).toMatchObject({ label: "yubikey" });
  });
});

describe("PkAuthCeremonyClient credentials guard", () => {
  it("throws a clear error when no credentials are injected and navigator lacks them", async () => {
    // jsdom does not implement navigator.credentials, so the fallback guard
    // fires. Kills the `if (this.credentials)` and navigator-check mutants.
    const { fetchImpl } = ceremonyFetch({
      "/registration/start": { challengeId: "ch-1", publicKey: CREATE_OPTIONS_JSON },
    });
    const client = new PkAuthCeremonyClient({
      apiBase: "https://x",
      fetch: fetchImpl as unknown as typeof fetch,
    });
    await expect(client.register({ username: "alice" })).rejects.toThrow(
      /navigator\.credentials is not available/,
    );
  });
});

class FakeAuthenticatorThatFailsGet extends FakeAuthenticator {
  override async get(options: CredentialRequestOptions): Promise<PublicKeyCredential | null> {
    return null;
  }
}

/** Records every request body keyed by the URL suffix, and serves canned responses. */
function ceremonyFetch(responses: Record<string, unknown>) {
  const bodies: Record<string, Record<string, unknown>> = {};
  const methods: Record<string, string | undefined> = {};
  const urls: string[] = [];
  const fetchImpl = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    const u = String(url);
    urls.push(u);
    const key = Object.keys(responses).find((suffix) => u.endsWith(suffix));
    if (!key) throw new Error("unexpected " + u);
    methods[key] = init?.method;
    if (init?.body) bodies[key] = JSON.parse(String(init.body));
    return new Response(JSON.stringify(responses[key]), { status: 200 });
  });
  return { fetchImpl, bodies, methods, urls };
}



