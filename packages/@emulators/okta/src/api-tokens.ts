import { createHash } from "node:crypto";
import type { Store } from "@emulators/core";
import type { OktaApiToken, OktaUser } from "./entities.js";
import { getOktaStore } from "./store.js";

// API tokens: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/ApiToken/
// "Tokens are valid for 30 days from creation or last use", and deactivating the user who created a token
// deprovisions it (https://developer.okta.com/docs/guides/create-an-api-token/main/).

const TOKEN_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
const REVOKED_KEY = "okta.revoked_api_tokens";

export function hashApiToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function apiTokenExpiresAt(token: OktaApiToken): string {
  return new Date(Date.parse(token.last_used_at) + TOKEN_WINDOW_MS).toISOString();
}

function markRevoked(store: Store, tokenHash: string): void {
  const revoked = store.getData<string[]>(REVOKED_KEY) ?? [];
  if (!revoked.includes(tokenHash)) store.setData(REVOKED_KEY, [...revoked, tokenHash]);
}

export function isRevokedApiToken(store: Store, token: string): boolean {
  return (store.getData<string[]>(REVOKED_KEY) ?? []).includes(hashApiToken(token));
}

export function findApiToken(store: Store, token: string): OktaApiToken | undefined {
  return getOktaStore(store).apiTokens.findOneBy("token_hash", hashApiToken(token));
}

export type ApiTokenCheck = { user: OktaUser; token: OktaApiToken } | "invalid" | "unknown";

/**
 * Resolves an `SSWS` token: a known, unexpired token of an existing user records its use and acts as that user;
 * a revoked or expired one is invalid; any other token is unknown to the API token store.
 */
export function useApiToken(store: Store, value: string): ApiTokenCheck {
  if (isRevokedApiToken(store, value)) return "invalid";
  const okta = getOktaStore(store);
  const token = findApiToken(store, value);
  if (!token) return "unknown";
  const user = okta.users.findOneBy("okta_id", token.user_okta_id);
  if (!user || Date.parse(apiTokenExpiresAt(token)) <= Date.now()) {
    revokeApiToken(store, token);
    return "invalid";
  }
  const used = okta.apiTokens.update(token.id, { last_used_at: new Date().toISOString() }) ?? token;
  return { user, token: used };
}

export function revokeApiToken(store: Store, token: OktaApiToken): void {
  markRevoked(store, token.token_hash);
  getOktaStore(store).apiTokens.delete(token.id);
}

/** Deprovisions the tokens a user created, as Okta does when the user is deactivated. */
export function revokeUserApiTokens(store: Store, userOktaId: string): void {
  for (const token of getOktaStore(store).apiTokens.findBy("user_okta_id", userOktaId)) revokeApiToken(store, token);
}

export function apiTokenResponse(baseUrl: string, token: OktaApiToken): Record<string, unknown> {
  return {
    name: token.name,
    userId: token.user_okta_id,
    tokenWindow: "P30D",
    network: { connection: "ANYWHERE" },
    id: token.token_id,
    clientName: "Okta API",
    expiresAt: apiTokenExpiresAt(token),
    created: token.created_at,
    lastUpdated: token.updated_at,
    _links: {
      self: {
        href: `${baseUrl}/api/v1/api-tokens/${encodeURIComponent(token.token_id)}`,
        hints: { allow: ["GET", "DELETE"] },
      },
      user: {
        href: `${baseUrl}/api/v1/users/${encodeURIComponent(token.user_okta_id)}`,
        hints: { allow: ["GET"] },
      },
    },
  };
}
