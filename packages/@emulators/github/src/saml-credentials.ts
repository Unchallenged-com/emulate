import { createHash, randomBytes } from "crypto";
import { ApiError, type AppEnv, type AuthUser, type Context, type Next, type Store } from "@emulators/core";
import { getGitHubStore, type GitHubStore } from "./store.js";
import type { GitHubCredentialKind, GitHubOrg } from "./entities.js";
import { isOrgMember } from "./route-helpers.js";

/** GitHub: the URL in the X-GitHub-SSO header "expires after one hour". */
export const AUTHORIZATION_REQUEST_TTL_MS = 60 * 60 * 1000;

type CredentialType = "personal access token" | "OAuth token";

interface CredentialContext {
  credentialHash: string;
  credentialType: CredentialType;
  omittedOrgIds: Set<number>;
}

/** What an authorization records about the credential, from the token itself and its owner. */
export interface AuthorizedCredential {
  hash: string;
  kind: GitHubCredentialKind;
  login: string | null;
  tokenLastEight: string;
  scopes: string[] | null;
}

/** A request to authorize a personal access token, the only credential the X-GitHub-SSO URL is documented for. */
export interface CredentialAuthorizationRequest {
  org_id: number;
  login: string;
  credential_hash: string;
  credential_kind: GitHubCredentialKind;
  token_last_eight: string;
  scopes: string[];
  created_at: number;
}

// The credential behind each request's user, keyed by the request's own copy of the AuthUser.
const credentialContexts = new WeakMap<AuthUser, CredentialContext>();

export function credentialHash(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/**
 * GitHub's token formats: OAuth access tokens begin with `gho_`, fine-grained personal access tokens
 * with `github_pat_`. Other user tokens count as classic personal access tokens.
 */
export function credentialKindOf(token: string): GitHubCredentialKind {
  if (token.startsWith("gho_")) return "oauth_app_token";
  if (token.startsWith("github_pat_")) return "fine_grained_pat";
  return "classic_pat";
}

function credentialTypeOf(token: string): CredentialType {
  return credentialKindOf(token) === "oauth_app_token" ? "OAuth token" : "personal access token";
}

export function describeCredential(token: string, login: string | null, scopes: string[] | null): AuthorizedCredential {
  return { hash: credentialHash(token), kind: credentialKindOf(token), login, tokenLastEight: token.slice(-8), scopes };
}

export class SamlSsoRequiredError extends ApiError {
  constructor(
    readonly orgId: number,
    credentialType: CredentialType,
  ) {
    super(
      403,
      `Resource protected by organization SAML enforcement. You must grant your ${
        credentialType === "OAuth token" ? "OAuth token" : "Personal Access token"
      } access to this organization.`,
    );
  }
}

/**
 * Whether the request's credential needs a SAML SSO authorization for the organization: the user is a
 * member (outside collaborators are exempt), the organization enforces SAML or the user has a linked
 * identity there, and the credential is not authorized. Tokens created by apps are always authorized.
 */
export function ssoAuthorizationRequired(gh: GitHubStore, authUser: AuthUser | undefined, orgId: number): boolean {
  if (!authUser || authUser.installation) return false;
  const context = credentialContexts.get(authUser);
  if (!context) return false;
  const config = gh.orgSamlConfigs.findOneBy("org_id", orgId);
  if (!config) return false;
  const user = gh.users.findOneBy("login", authUser.login);
  if (!user || !isOrgMember(gh, user.id, orgId)) return false;
  const linked = gh.samlIdentities.findBy("org_id", orgId).some((identity) => identity.user_id === user.id);
  if (!config.enforced && !linked) return false;
  const authorization = gh.credentialAuthorizations
    .findBy("org_id", orgId)
    .find((row) => row.credential_hash === context.credentialHash);
  if (!authorization) return true;
  gh.credentialAuthorizations.update(authorization.id, { credential_accessed_at: new Date().toISOString() });
  return false;
}

export function assertSsoAuthorized(gh: GitHubStore, authUser: AuthUser | undefined, orgId: number): void {
  if (!ssoAuthorizationRequired(gh, authUser, orgId)) return;
  throw new SamlSsoRequiredError(orgId, credentialContexts.get(authUser!)!.credentialType);
}

/** Records that a list left out an organization's resources because the credential is not authorized. */
export function noteSsoOmittedOrg(authUser: AuthUser | undefined, orgId: number): void {
  if (authUser) credentialContexts.get(authUser)?.omittedOrgIds.add(orgId);
}

/** The ID of the underlying token: the same across every authorization of that token. */
function authorizedCredentialId(store: Store, hash: string): number {
  let ids = store.getData<Map<string, number>>("github.saml.authorizedCredentialIds");
  if (!ids) {
    ids = new Map();
    store.setData("github.saml.authorizedCredentialIds", ids);
  }
  let id = ids.get(hash);
  if (id === undefined) {
    id = ids.size + 1;
    ids.set(hash, id);
  }
  return id;
}

export function authorizeCredential(store: Store, orgId: number, credential: AuthorizedCredential): void {
  const gh = getGitHubStore(store);
  const existing = gh.credentialAuthorizations
    .findBy("org_id", orgId)
    .some((row) => row.credential_hash === credential.hash);
  if (existing) return;
  gh.credentialAuthorizations.insert({
    org_id: orgId,
    credential_hash: credential.hash,
    credential_kind: credential.kind,
    login: credential.login,
    token_last_eight: credential.tokenLastEight,
    scopes: credential.scopes,
    authorized_credential_id: authorizedCredentialId(store, credential.hash),
    credential_accessed_at: null,
  });
}

export function seedAuthorizedTokens(store: Store, org: GitHubOrg, tokens: string[]): void {
  for (const token of tokens) authorizeCredential(store, org.id, describeCredential(token, null, null));
}

function getAuthorizationRequests(store: Store): Map<string, CredentialAuthorizationRequest> {
  let map = store.getData<Map<string, CredentialAuthorizationRequest>>("github.saml.credentialAuthorizationRequests");
  if (!map) {
    map = new Map();
    store.setData("github.saml.credentialAuthorizationRequests", map);
  }
  return map;
}

function createAuthorizationRequest(store: Store, request: CredentialAuthorizationRequest): string {
  const requests = getAuthorizationRequests(store);
  for (const [id, existing] of requests) {
    if (request.created_at - existing.created_at >= AUTHORIZATION_REQUEST_TTL_MS) requests.delete(id);
  }
  const id = randomBytes(20).toString("hex");
  requests.set(id, request);
  return id;
}

/** An authorization request less than one hour old, if it exists. */
export function getAuthorizationRequest(store: Store, id: string): CredentialAuthorizationRequest | null {
  const requests = getAuthorizationRequests(store);
  const request = requests.get(id);
  if (!request) return null;
  if (Date.now() - request.created_at >= AUTHORIZATION_REQUEST_TTL_MS) {
    requests.delete(id);
    return null;
  }
  return request;
}

export function deleteAuthorizationRequest(store: Store, id: string): void {
  getAuthorizationRequests(store).delete(id);
}

/**
 * Registered before the routes. Gives each request with a user token its own credential context,
 * answers a refused personal access token with `X-GitHub-SSO: required; url=...`, and a list that
 * left out organizations with `X-GitHub-SSO: partial-results; organizations=...`. GitHub documents
 * the header for personal access tokens only: an OAuth token is authorized by authorizing the app
 * again during an active SAML session, so its refusals carry no header. Inactive until an
 * organization has SAML configured.
 */
export function samlCredentialMiddleware(store: Store, baseUrl: string) {
  return async (c: Context<AppEnv>, next: Next) => {
    const gh = getGitHubStore(store);
    const authUser = c.get("authUser");
    const token = c.get("authToken");
    if (!authUser || authUser.installation || !token || gh.orgSamlConfigs.all().length === 0) {
      await next();
      return;
    }

    const scoped: AuthUser = { ...authUser };
    const context: CredentialContext = {
      credentialHash: credentialHash(token),
      credentialType: credentialTypeOf(token),
      omittedOrgIds: new Set(),
    };
    credentialContexts.set(scoped, context);
    c.set("authUser", scoped);

    const personalAccessToken = context.credentialType === "personal access token";
    try {
      await next();
    } catch (error) {
      const org = error instanceof SamlSsoRequiredError ? gh.orgs.get(error.orgId) : undefined;
      if (org && personalAccessToken) {
        const id = createAuthorizationRequest(store, {
          org_id: org.id,
          login: authUser.login,
          credential_hash: context.credentialHash,
          credential_kind: credentialKindOf(token),
          token_last_eight: token.slice(-8),
          scopes: [...authUser.scopes],
          created_at: Date.now(),
        });
        const returnTo = `/orgs/${org.login}/sso?authorization_request=${id}`;
        c.header("X-GitHub-SSO", `required; url=${baseUrl}/login/sso?return_to=${encodeURIComponent(returnTo)}`);
      }
      throw error;
    }

    if (personalAccessToken && context.omittedOrgIds.size > 0) {
      c.header("X-GitHub-SSO", `partial-results; organizations=${[...context.omittedOrgIds].join(",")}`);
    }
  };
}
