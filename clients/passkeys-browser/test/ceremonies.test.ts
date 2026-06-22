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
import {RegistrationService} from "./helpers/registration";
import {FakeAuthenticator} from "./helpers/fakeAuthenticator";

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
      [startPath]: errorHttpHandler,
    });
    const credentialsContainer = noOpCredentialsContainer();
    const client = new PkAuthCeremonyClient(
      { apiBase: server.url },
      { credentials: credentialsContainer },
    );

    await expect(client.register({ username: "alice", label: "key" })).rejects.toThrow("HTTP 500: unit test error from errorHttpHandler");

    expect(credentialsContainer.create).not.toHaveBeenCalled(); // this proves the client did not attempt to create a credential upon failure to start registration.ts
  })

  it("when start registration succeeds but no credential is created, then the client fails with credential cancellation", async() => {
    const registration = new RegistrationService("localhost", "alice", "bob")
    using server= await startHttpServer({
      [startPath]: newStartHandler(registration),
      [finishPath]: newFinishHandler(registration)
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
    const registration = new RegistrationService("localhost", "alice", "bob")
    using server= await startHttpServer({
      [startPath]: newStartHandler(registration),
      [finishPath]: errorHttpHandler
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
    const registration = new RegistrationService("localhost", "alice", "bob")
    using server = await startHttpServer({
      [startPath]: newStartHandler(registration),
      [finishPath]: newFinishHandler(registration)
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

  const startPath = "/auth/passkeys/registration/start";
  const finishPath = "/auth/passkeys/registration/finish"

  function noOpCredentialsContainer() : CredentialsContainer {
    return { create: vi.fn(), get: vi.fn(), preventSilentAccess: vi.fn(), store: vi.fn()};
  }

  function errorHttpHandler(_: http.IncomingMessage, res: http.ServerResponse) : void {
    res.writeHead(500)
    res.end("unit test error from errorHttpHandler")
  }

  function newStartHandler(registration: RegistrationService) : HttpHandler{
    const endpoint = async (req: StartRegistrationRequest) : Promise<StartRegistrationResponse> => {
      return registration.start(req);
    };
    const handler = new Handler(decodePost, endpoint, encodeJson);
    return newHttpHandler(handler);
  }

  function newFinishHandler(registration: RegistrationService) : HttpHandler{
    const endpoint = async (req: FinishRegistrationRequest) : Promise<FinishRegistrationResponse> => {
      return registration.finish(req);
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

describe("PkAuthCeremonyClient.authenticate (end-to-end with stubbed credentials)", () => {
  it("walks start -> get -> finish and returns the token", async () => {
    const { fetchImpl, bodies, methods, urls } = ceremonyFetch({
      "/authentication/start": { challengeId: "ch-9", publicKey: REQUEST_OPTIONS_JSON },
      "/authentication/finish": { token: "jwt-token" },
    });
    const get = vi.fn(async () => fakeAssertion(new Uint8Array([42])));
    const fakeCreds = { create: vi.fn(), get } as unknown as CredentialsContainer;
    const client = new PkAuthCeremonyClient(
      { apiBase: "https://x", fetch: fetchImpl as unknown as typeof fetch },
      { credentials: fakeCreds },
    );

    const result = await client.authenticate({ username: "alice" });

    expect(result.token).toBe("jwt-token");
    expect(get).toHaveBeenCalledOnce();
    expect(bodies["/authentication/start"]).toMatchObject({ username: "alice", challenge: null });
    expect(bodies["/authentication/finish"]).toMatchObject({ challengeId: "ch-9" });
    expect(methods["/authentication/start"]).toBe("POST");
    expect(methods["/authentication/finish"]).toBe("POST");
    expect(urls.some((u) => u.endsWith("/authentication/start"))).toBe(true);
  });

  it("defaults username to null when omitted", async () => {
    const { fetchImpl, bodies } = ceremonyFetch({
      "/authentication/start": { challengeId: "ch-9", publicKey: REQUEST_OPTIONS_JSON },
      "/authentication/finish": { token: "t" },
    });
    const fakeCreds = {
      create: vi.fn(),
      get: vi.fn(async () => fakeAssertion(new Uint8Array([1]))),
    } as unknown as CredentialsContainer;
    const client = new PkAuthCeremonyClient(
      { apiBase: "https://x", fetch: fetchImpl as unknown as typeof fetch },
      { credentials: fakeCreds },
    );
    await client.authenticate();
    // username ?? null  (kills the `&&` mutant): no username -> explicit null.
    expect(bodies["/authentication/start"]).toMatchObject({ username: null });
  });

  it("requests conditional mediation only when conditional=true", async () => {
    const responses = {
      "/authentication/start": { challengeId: "ch-9", publicKey: REQUEST_OPTIONS_JSON },
      "/authentication/finish": { token: "t" },
    };
    // conditional = true -> mediation set
    const getCond = vi.fn(async (_options?: CredentialRequestOptions) => fakeAssertion(new Uint8Array([1])));
    const a = ceremonyFetch(responses);
    await new PkAuthCeremonyClient(
      { apiBase: "https://x", fetch: a.fetchImpl as unknown as typeof fetch },
      { credentials: { create: vi.fn(), get: getCond } as unknown as CredentialsContainer },
    ).authenticate({ conditional: true });
    expect(
      (getCond.mock.calls[0]![0] as CredentialRequestOptions & { mediation?: string }).mediation,
    ).toBe("conditional");

    // conditional defaults to false -> no mediation
    const getPlain = vi.fn(async (_options?: CredentialRequestOptions) => fakeAssertion(new Uint8Array([1])));
    const b = ceremonyFetch(responses);
    await new PkAuthCeremonyClient(
      { apiBase: "https://x", fetch: b.fetchImpl as unknown as typeof fetch },
      { credentials: { create: vi.fn(), get: getPlain } as unknown as CredentialsContainer },
    ).authenticate();
    expect(
      (getPlain.mock.calls[0]![0] as CredentialRequestOptions & { mediation?: string }).mediation,
    ).toBeUndefined();
  });

  it("rejects when the authenticator returns no credential (get cancelled)", async () => {
    const { fetchImpl } = ceremonyFetch({
      "/authentication/start": { challengeId: "ch-9", publicKey: REQUEST_OPTIONS_JSON },
    });
    const fakeCreds = { create: vi.fn(), get: vi.fn(async () => null) } as unknown as CredentialsContainer;
    const client = new PkAuthCeremonyClient(
      { apiBase: "https://x", fetch: fetchImpl as unknown as typeof fetch },
      { credentials: fakeCreds },
    );
    await expect(client.authenticate()).rejects.toThrow(/authentication was cancelled/);
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


// Additional ceremony coverage driven by the StrykerJS report (PR #39, @bernata):
// the suite previously exercised only the register() happy path, leaving
// authenticate(), the credential create/get helpers, the cancellation branches,
// and the navigator.credentials guard as 0%-covered (every mutant survived).
// These ceremonies ARE unit-testable because CeremonyOptions.credentials injects
// a fake CredentialsContainer — so we drive the full flows here.

function fakeAssertion(rawId: Uint8Array): PublicKeyCredential {
  return fakeCredential(rawId, {
    clientDataJSON: new Uint8Array([0x7b]).buffer as ArrayBuffer,
    authenticatorData: new Uint8Array([0x55]).buffer as ArrayBuffer,
    signature: new Uint8Array([0x99]).buffer as ArrayBuffer,
    userHandle: null,
  } as unknown as AuthenticatorResponse);
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



