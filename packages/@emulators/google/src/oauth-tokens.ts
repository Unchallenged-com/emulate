import { randomBytes } from "node:crypto";
import type { Store, TokenMap } from "@emulators/core";
import type { GoogleUser } from "./entities.js";

interface AccessTokenRecord {
  email: string;
  scopes: string[];
  expiresAt: number;
  refreshToken: string;
}

interface RefreshTokenRecord {
  email: string;
  scope: string;
  clientId: string;
}

export function getAccessTokens(store: Store): Map<string, AccessTokenRecord> {
  let tokens = store.getData<Map<string, AccessTokenRecord>>("google.oauth.accessTokens");
  if (!tokens) {
    tokens = new Map();
    store.setData("google.oauth.accessTokens", tokens);
  }
  return tokens;
}

export function getRefreshTokens(store: Store): Map<string, RefreshTokenRecord> {
  let tokens = store.getData<Map<string, RefreshTokenRecord>>("google.oauth.refreshTokens");
  if (!tokens) {
    tokens = new Map();
    store.setData("google.oauth.refreshTokens", tokens);
  }
  return tokens;
}

export function issueAccessToken(
  store: Store,
  tokenMap: TokenMap | undefined,
  user: GoogleUser,
  scope: string,
  refreshToken: string,
): string {
  const token = "google_" + randomBytes(20).toString("base64url");
  const scopes = scope.split(/\s+/).filter(Boolean);
  tokenMap?.set(token, { login: user.email, id: user.id, scopes });
  getAccessTokens(store).set(token, {
    email: user.email,
    scopes: scope ? scopes : ["openid", "email", "profile"],
    expiresAt: Date.now() + 3600 * 1000,
    refreshToken,
  });
  return token;
}

/** The user and client a token was issued for, if it is a live access or refresh token. */
function grantOf(store: Store, token: string): { email: string; clientId?: string } | undefined {
  const refreshTokens = getRefreshTokens(store);
  const access = getAccessTokens(store).get(token);
  if (access) return { email: access.email, clientId: refreshTokens.get(access.refreshToken)?.clientId };
  const refresh = refreshTokens.get(token);
  return refresh && { email: refresh.email, clientId: refresh.clientId };
}

/** Ends every access and refresh token `email` holds for `clientId`. */
export function revokeClientTokens(store: Store, tokenMap: TokenMap | undefined, email: string, clientId: string) {
  const accessTokens = getAccessTokens(store);
  const refreshTokens = getRefreshTokens(store);
  const revoked = new Set<string>();
  for (const [refreshToken, record] of refreshTokens) {
    if (record.email === email && record.clientId === clientId) {
      revoked.add(refreshToken);
      refreshTokens.delete(refreshToken);
    }
  }
  for (const [accessToken, record] of accessTokens) {
    if (revoked.has(record.refreshToken)) {
      accessTokens.delete(accessToken);
      tokenMap?.delete(accessToken);
    }
  }
}

/** Revokes `token`; returns false when it is not a live token the emulator issued. */
export function revokeToken(store: Store, tokenMap: TokenMap | undefined, token: string): boolean {
  const grant = grantOf(store, token);
  if (store.getData<boolean>("google.strict_scopes") === true && grant?.clientId !== undefined) {
    // "Revocation removes all OAuth 2.0 scopes previously granted to a project, invalidating any issued access or
    // refresh tokens for all clients registered under that project."
    // (https://developers.google.com/identity/protocols/oauth2/web-server#tokenrevoke) The emulator has no projects:
    // each client stands for its own.
    revokeClientTokens(store, tokenMap, grant.email, grant.clientId);
  }
  getAccessTokens(store).delete(token);
  tokenMap?.delete(token);
  getRefreshTokens(store).delete(token);
  return grant !== undefined;
}

/** The scopes `email` granted each client, from its live refresh tokens, keyed by client ID. */
export function clientGrants(store: Store, email: string): Map<string, string[]> {
  const grants = new Map<string, Set<string>>();
  for (const record of getRefreshTokens(store).values()) {
    if (record.email !== email) continue;
    const scopes = grants.get(record.clientId) ?? new Set<string>();
    const granted = record.scope.split(/\s+/).filter(Boolean);
    for (const scope of granted.length > 0 ? granted : ["openid", "email", "profile"]) scopes.add(scope);
    grants.set(record.clientId, scopes);
  }
  return new Map([...grants].map(([clientId, scopes]) => [clientId, [...scopes]]));
}
