// SPDX-License-Identifier: MIT

import * as b64u from "./base64url";
import { request } from "./http";
import type {
  ClientOptions,
  FinishAuthenticationRequest,
  FinishAuthenticationResponse,
  FinishRegistrationRequest,
  FinishRegistrationResponse,
  PublicKeyCredentialCreationOptionsJson,
  PublicKeyCredentialRequestOptionsJson,
  RegistrationResponseJson,
  AuthenticationResponseJson,
  StartAuthenticationRequest,
  StartAuthenticationResponse,
  StartRegistrationRequest,
  StartRegistrationResponse,
} from "./types";

const PATHS = {
  startReg: "/auth/passkeys/registration/start",
  finishReg: "/auth/passkeys/registration/finish",
  startAuth: "/auth/passkeys/authentication/start",
  finishAuth: "/auth/passkeys/authentication/finish",
} as const;

// All three adapters (Spring, Dropwizard, Micronaut) mount ceremony endpoints at
// /auth/passkeys/<phase>/<step>. The `paths` override is an escape hatch for hosts that
// remap the routes; no pk-auth-provided adapter needs it.

export interface CeremonyOptions {
  /** Path overrides, an escape hatch for hosts that remap pk-auth's default routes. */
  paths?: Partial<typeof PATHS>;
  /** Replacement for `navigator.credentials`, for tests and non-browser callers. */
  credentials?: CredentialsContainer;
}

export interface StartRegistrationParams {
  username: string;
  displayName?: string;
  label?: string;
}

export interface FinishRegistrationParams extends StartRegistrationResponse {
  username: string;
  label?: string;
}

export interface StartAuthenticationParams {
  username?: string;
  /** When true, hands the call to `navigator.credentials.get` with `mediation: "conditional"`. */
  conditional?: boolean;
}

export class PkAuthCeremonyClient {
  private readonly client: ClientOptions;
  private readonly paths: typeof PATHS;
  private readonly credentials?: CredentialsContainer;

  constructor(client: ClientOptions, options: CeremonyOptions = {}) {
    this.client = client;
    this.paths = { ...PATHS, ...options.paths };
    this.credentials = options.credentials;
  }

  /**
   * Runs the full registration ceremony: server-start → `navigator.credentials.create` →
   * server-finish. Returns the finish payload (registered credential metadata).
   */
  async register(params: StartRegistrationParams): Promise<FinishRegistrationResponse> {
    const start = await this.startRegistration({
      username: params.username,
      displayName: params.displayName ?? params.username,
      label: params.label ?? null,
      challenge: null,
    });
    const created = await this.createCredential(start.publicKey);
    return this.finishRegistration({
      challengeId: start.challengeId,
      username: params.username,
      label: params.label ?? null,
      response: encodeRegistrationResponse(created),
    });
  }

  /**
   * Runs the full sign-in ceremony: server-start → `navigator.credentials.get` →
   * server-finish. Returns the JWT; the caller stores it.
   */
  async authenticate(params: StartAuthenticationParams = {}): Promise<FinishAuthenticationResponse> {
    const start = await this.startAuthentication({
      username: params.username ?? null,
      challenge: null,
    });
    const got = await this.getCredential(start.publicKey, params.conditional ?? false);
    return this.finishAuthentication({
      challengeId: start.challengeId,
      response: encodeAuthenticationResponse(got),
    });
  }

  startRegistration(body: StartRegistrationRequest): Promise<StartRegistrationResponse> {
    return request(this.client, "POST", this.paths.startReg, body, false);
  }

  finishRegistration(body: FinishRegistrationRequest): Promise<FinishRegistrationResponse> {
    return request(this.client, "POST", this.paths.finishReg, body, false);
  }

  startAuthentication(body: StartAuthenticationRequest): Promise<StartAuthenticationResponse> {
    return request(this.client, "POST", this.paths.startAuth, body, false);
  }

  finishAuthentication(body: FinishAuthenticationRequest): Promise<FinishAuthenticationResponse> {
    return request(this.client, "POST", this.paths.finishAuth, body, false);
  }

  private get credentialsImpl(): CredentialsContainer {
    if (this.credentials) return this.credentials;
    if (typeof navigator === "undefined" || !navigator.credentials) {
      throw new Error("pk-auth: navigator.credentials is not available in this environment");
    }
    return navigator.credentials;
  }

  private async createCredential(
    options: PublicKeyCredentialCreationOptionsJson,
  ): Promise<PublicKeyCredential> {
    const publicKey = decodeCreationOptions(options);
    const credential = (await this.credentialsImpl.create({ publicKey })) as PublicKeyCredential | null;
    if (!credential) {
      throw new Error("pk-auth: credential creation was cancelled");
    }
    return credential;
  }

  private async getCredential(
    options: PublicKeyCredentialRequestOptionsJson,
    conditional: boolean,
  ): Promise<PublicKeyCredential> {
    const publicKey = decodeRequestOptions(options);
    const request: CredentialRequestOptions = { publicKey };
    if (conditional) {
      (request as CredentialRequestOptions & { mediation?: string }).mediation = "conditional";
    }
    const credential = (await this.credentialsImpl.get(request)) as PublicKeyCredential | null;
    if (!credential) {
      throw new Error("pk-auth: authentication was cancelled");
    }
    return credential;
  }
}

export function decodeCreationOptions(
  options: PublicKeyCredentialCreationOptionsJson,
): PublicKeyCredentialCreationOptions {
  return {
    rp: options.rp,
    user: {
      id: b64u.decodeToArrayBuffer(options.user.id),
      name: options.user.name,
      displayName: options.user.displayName,
    },
    challenge: b64u.decodeToArrayBuffer(options.challenge),
    pubKeyCredParams: options.pubKeyCredParams,
    timeout: options.timeout,
    attestation: options.attestation,
    authenticatorSelection: options.authenticatorSelection,
    excludeCredentials: (options.excludeCredentials ?? []).map((c) => ({
      id: b64u.decodeToArrayBuffer(c.id),
      type: c.type,
      transports: c.transports as AuthenticatorTransport[] | undefined,
    })),
  };
}

export function decodeRequestOptions(
  options: PublicKeyCredentialRequestOptionsJson,
): PublicKeyCredentialRequestOptions {
  return {
    challenge: b64u.decodeToArrayBuffer(options.challenge),
    timeout: options.timeout,
    rpId: options.rpId,
    userVerification: options.userVerification,
    allowCredentials: (options.allowCredentials ?? []).map((c) => ({
      id: b64u.decodeToArrayBuffer(c.id),
      type: c.type,
      transports: c.transports as AuthenticatorTransport[] | undefined,
    })),
  };
}

export function encodeRegistrationResponse(credential: PublicKeyCredential): RegistrationResponseJson {
  const response = credential.response as AuthenticatorAttestationResponse;
  const transports =
    typeof (response as AuthenticatorAttestationResponse & {
      getTransports?: () => string[];
    }).getTransports === "function"
      ? (response as AuthenticatorAttestationResponse & {
          getTransports: () => string[];
        }).getTransports()
      : [];
  return {
    id: b64u.encode(credential.rawId),
    rawId: b64u.encode(credential.rawId),
    type: "public-key",
    response: {
      clientDataJSON: b64u.encode(response.clientDataJSON),
      attestationObject: b64u.encode(response.attestationObject),
      transports,
    },
  };
}

export function encodeAuthenticationResponse(
  credential: PublicKeyCredential,
): AuthenticationResponseJson {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: b64u.encode(credential.rawId),
    rawId: b64u.encode(credential.rawId),
    type: "public-key",
    response: {
      clientDataJSON: b64u.encode(response.clientDataJSON),
      authenticatorData: b64u.encode(response.authenticatorData),
      signature: b64u.encode(response.signature),
      userHandle: response.userHandle ? b64u.encode(response.userHandle) : null,
    },
  };
}
