// SPDX-License-Identifier: MIT

import { PkAuthHttpError, request } from "./http";
import type { ClientOptions } from "./types";

/** Typed success: a fresh refresh and access token pair. */
export interface RefreshSuccess {
  readonly kind: "success";
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly expiresAt: string;
}

/** Typed failure mirroring the {@code detail} field on the server's 401 body. */
export type RefreshFailureReason = "expired" | "unknown" | "replayed" | "revoked";

export interface RefreshFailure {
  readonly kind: "failure";
  readonly reason: RefreshFailureReason;
  /** Categorical revoke reason when `reason === "revoked"`. */
  readonly revokeReason?: string;
}

/** Sealed sum of refresh outcomes. */
export type RefreshResult = RefreshSuccess | RefreshFailure;

/** Type guard for {@link RefreshSuccess}. */
export function isRefreshSuccess(r: RefreshResult): r is RefreshSuccess {
  return r.kind === "success";
}

/** Type guard for {@link RefreshFailure}. */
export function isRefreshFailure(r: RefreshResult): r is RefreshFailure {
  return r.kind === "failure";
}

interface RawRefreshResponse {
  refreshToken: string;
  accessToken: string;
  expiresAt: string;
}

interface RawErrorResponse {
  detail?: string;
  reason?: string;
}

/**
 * Client for the {@code POST /auth/refresh} endpoint shipped by every pk-auth adapter. Returns
 * a typed {@link RefreshResult} rather than throwing on 401. The bearer's expected response to
 * an unknown, expired, replayed, or revoked outcome is to redirect to login, not to handle an
 * exception.
 *
 * @since 1.1.0
 */
export class PkAuthRefreshClient {
  private readonly options: ClientOptions;
  private readonly path: string;

  constructor(options: ClientOptions, path: string = "/auth/refresh") {
    this.options = options;
    this.path = path;
  }

  async refresh(refreshToken: string): Promise<RefreshResult> {
    try {
      const response = await request<RawRefreshResponse>(
        this.options,
        "POST",
        this.path,
        { refreshToken },
        false,
      );
      return {
        kind: "success",
        accessToken: response.accessToken,
        refreshToken: response.refreshToken,
        expiresAt: response.expiresAt,
      };
    } catch (e: unknown) {
      if (e instanceof PkAuthHttpError && e.status === 401) {
        const data = e.data as RawErrorResponse | undefined;
        const detail = data?.detail;
        if (
          detail === "expired" ||
          detail === "unknown" ||
          detail === "replayed" ||
          detail === "revoked"
        ) {
          return { kind: "failure", reason: detail, revokeReason: data?.reason };
        }
        // A 401 the client does not recognise surfaces as the most conservative failure.
        return { kind: "failure", reason: "unknown" };
      }
      throw e;
    }
  }
}
