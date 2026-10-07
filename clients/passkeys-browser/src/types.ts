// SPDX-License-Identifier: MIT

import type { Base64Url } from "./base64url";

/** Caller-supplied bearer-token accessor. Returns null when no session exists. */
export type TokenAccessor = () => string | null;

/** Construction options shared by the ceremony and admin clients. */
export interface ClientOptions {
  /** Base URL for all pk-auth endpoints. Trailing slash is tolerated. */
  apiBase: string;
  /**
   * Returns the current bearer token (null when unauthenticated). Required for admin operations;
   * ceremony operations are anonymous and will not call it.
   */
  getToken?: TokenAccessor;
  /** Replacement for the global `fetch`, used in tests. */
  fetch?: typeof fetch;
}

// Ceremony wire shapes

export interface RpEntity {
  id: string;
  name: string;
}

export interface PublicKeyCredentialUserEntityJson {
  id: Base64Url;
  name: string;
  displayName: string;
}

export interface PublicKeyCredentialDescriptorJson {
  id: Base64Url;
  type: "public-key";
  transports?: string[];
}

export interface PublicKeyCredentialCreationOptionsJson {
  rp: RpEntity;
  user: PublicKeyCredentialUserEntityJson;
  challenge: Base64Url;
  pubKeyCredParams: { type: "public-key"; alg: number }[];
  timeout?: number;
  excludeCredentials?: PublicKeyCredentialDescriptorJson[];
  authenticatorSelection?: {
    authenticatorAttachment?: "platform" | "cross-platform";
    residentKey?: "discouraged" | "preferred" | "required";
    requireResidentKey?: boolean;
    userVerification?: "discouraged" | "preferred" | "required";
  };
  attestation?: "none" | "indirect" | "direct" | "enterprise";
}

export interface PublicKeyCredentialRequestOptionsJson {
  challenge: Base64Url;
  timeout?: number;
  rpId?: string;
  allowCredentials?: PublicKeyCredentialDescriptorJson[];
  userVerification?: "discouraged" | "preferred" | "required";
}

export interface StartRegistrationRequest {
  username: string;
  displayName?: string | null;
  label?: string | null;
  challenge?: Base64Url | null;
}

export interface StartRegistrationResponse {
  challengeId: string;
  publicKey: PublicKeyCredentialCreationOptionsJson;
}

export interface StartAuthenticationRequest {
  username?: string | null;
  challenge?: Base64Url | null;
}

export interface StartAuthenticationResponse {
  challengeId: string;
  publicKey: PublicKeyCredentialRequestOptionsJson;
}

export interface RegistrationResponseJson {
  id: Base64Url;
  rawId: Base64Url;
  type: "public-key";
  response: {
    clientDataJSON: Base64Url;
    attestationObject: Base64Url;
    transports?: string[];
  };
}

export interface AuthenticationResponseJson {
  id: Base64Url;
  rawId: Base64Url;
  type: "public-key";
  response: {
    clientDataJSON: Base64Url;
    authenticatorData: Base64Url;
    signature: Base64Url;
    userHandle: Base64Url | null;
  };
}

export interface FinishRegistrationRequest {
  challengeId: string;
  username: string;
  label?: string | null;
  response: RegistrationResponseJson;
}

export interface FinishAuthenticationRequest {
  challengeId: string;
  response: AuthenticationResponseJson;
}

/** The server returns the wrapped RegistrationResult; the relevant fields are surfaced here. */
export interface FinishRegistrationResponse {
  credential: {
    credentialId: Base64Url;
    userHandle: Base64Url;
    label: string;
    transports: string[];
    counter: number;
    backupEligible: boolean;
    backupState: boolean;
    aaguid?: string | null;
    authenticatorData: Base64Url;
  };
}

export interface FinishAuthenticationResponse {
  token: string;
}

// Admin wire shapes

export interface CredentialSummary {
  credentialId: Base64Url;
  label: string;
  createdAt: string;
  lastUsedAt?: string | null;
  counter: number;
  backupEligible: boolean;
  backupState: boolean;
  transports: string[];
}

export interface AccountSummary {
  userHandle: Base64Url;
  username: string;
  displayName: string;
  emailVerified: boolean;
  phoneVerified: boolean;
  credentialCount: number;
  backupCodesRemaining: number;
}

export interface BackupCodeBatch {
  codes: string[];
}

export interface BackupCodeCount {
  remaining: number;
}

export interface EmailDispatchResult {
  /** Implementation-defined token / link reference returned by the dispatcher. */
  dispatchId?: string;
  /** Magic-link token (testkit and development only; real dispatchers send it out of band). */
  token?: string;
}

export interface PhoneDispatchResult {
  dispatchId?: string;
  /** OTP code (testkit and development only; real dispatchers send it via SMS). */
  code?: string;
}

export interface EmailVerificationResult {
  email: string;
  verified: boolean;
}

export interface PhoneVerificationResult {
  phone: string;
  verified: boolean;
}
