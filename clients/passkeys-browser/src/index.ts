// SPDX-License-Identifier: MIT

export * as base64url from "./base64url";
export { PkAuthHttpError } from "./http";
export type { CeremonyResult } from "./results";
export { isCeremonySuccess, isCeremonyFailure } from "./results";
export {
  PkAuthCeremonyClient,
  decodeCreationOptions,
  decodeRequestOptions,
  encodeAuthenticationResponse,
  encodeRegistrationResponse,
} from "./ceremonies";
export type {
  CeremonyOptions,
  FinishRegistrationParams,
  StartAuthenticationParams,
  StartRegistrationParams,
} from "./ceremonies";
export { PkAuthAdminClient } from "./admin";
export { PkAuthRefreshClient, isRefreshSuccess, isRefreshFailure } from "./refresh";
export type {
  RefreshResult,
  RefreshSuccess,
  RefreshFailure,
  RefreshFailureReason,
} from "./refresh";
export type * from "./types";

import { PkAuthAdminClient } from "./admin";
import { PkAuthCeremonyClient } from "./ceremonies";
import type { CeremonyOptions } from "./ceremonies";
import { PkAuthRefreshClient, type RefreshResult } from "./refresh";
import type { ClientOptions } from "./types";

/** Convenience facade: a single object exposing ceremony, admin, and refresh clients. */
export class PkAuthClient {
  readonly ceremonies: PkAuthCeremonyClient;
  readonly admin: PkAuthAdminClient;
  readonly refreshClient: PkAuthRefreshClient;

  constructor(options: ClientOptions, ceremonyOptions: CeremonyOptions = {}) {
    this.ceremonies = new PkAuthCeremonyClient(options, ceremonyOptions);
    this.admin = new PkAuthAdminClient(options);
    this.refreshClient = new PkAuthRefreshClient(options);
  }

  /**
   * Convenience shortcut to {@link PkAuthRefreshClient#refresh}. Returns a typed
   * {@link RefreshResult} sum and does not throw on 401.
   *
   * @since 1.1.0
   */
  refresh(refreshToken: string): Promise<RefreshResult> {
    return this.refreshClient.refresh(refreshToken);
  }
}
