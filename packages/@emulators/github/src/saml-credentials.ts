import { createHash, randomBytes } from "crypto";
import { ApiError, type AppEnv, type AuthUser, type Context, type Next, type Store } from "@emulators/core";
import { getGitHubStore, type GitHubStore } from "./store.js";
import type { GitHubCredentialAuthorization, GitHubOrg } from "./entities.js";
import { isOrgMember } from "./route-helpers.js";

/** GitHub: the URL in the X-GitHub-SSO header "expires after one hour". */
export const AUTHORIZATION_REQUEST_TTL_MS = 60 * 60 * 1000;

type CredentialType = GitHubCredentialAuthorization["credential_type"];

interface CredentialContext {
  credentialHash: string;
  credentialType: CredentialType;
  omittedOrgIds: Set<number>;
}

export interface CredentialAuthorizationRequest {
  org_id: number;
  login: string;
  credential_hash: string;
  credential_type: CredentialType;
  created_at: number;
}

// The credential behind each request's user, keyed by the request's own copy of the AuthUser.
const credentialContexts = new WeakMap<AuthUser, CredentialContext>();

export function credentialHash(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/** GitHub's token formats: OAuth access tokens begin with `gho_`. */
function credentialTypeOf(token: string): CredentialType {
  return token.startsWith("gho_") ? "OAuth token" : "personal access token";
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
  return !gh.credentialAuthorizations
    .findBy("org_id", orgId)
    .some((authorization) => authorization.credential_hash === context.credentialHash);
}

export function assertSsoAuthorized(gh: GitHubStore, authUser: AuthUser | undefined, orgId: number): void {
  if (!ssoAuthorizationRequired(gh, authUser, orgId)) return;
  throw new SamlSsoRequiredError(orgId, credentialContexts.get(authUser!)!.credentialType);
}

/** Records that a list left out an organization's resources because the credential is not authorized. */
export function noteSsoOmittedOrg(authUser: AuthUser | undefined, orgId: number): void {
  if (authUser) credentialContexts.get(authUser)?.omittedOrgIds.add(orgId);
}

export function authorizeCredential(store: Store, orgId: number, hash: string, type: CredentialType): void {
  const gh = getGitHubStore(store);
  const existing = gh.credentialAuthorizations.findBy("org_id", orgId).some((row) => row.credential_hash === hash);
  if (!existing) gh.credentialAuthorizations.insert({ org_id: orgId, credential_hash: hash, credential_type: type });
}

export function seedAuthorizedTokens(store: Store, org: GitHubOrg, tokens: string[]): void {
  for (const token of tokens) authorizeCredential(store, org.id, credentialHash(token), credentialTypeOf(token));
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
 * answers a refused credential with `X-GitHub-SSO: required; url=...`, and a list that left out
 * organizations with `X-GitHub-SSO: partial-results; organizations=...`. Inactive until an
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

    try {
      await next();
    } catch (error) {
      const org = error instanceof SamlSsoRequiredError ? gh.orgs.get(error.orgId) : undefined;
      if (org) {
        const id = createAuthorizationRequest(store, {
          org_id: org.id,
          login: authUser.login,
          credential_hash: context.credentialHash,
          credential_type: context.credentialType,
          created_at: Date.now(),
        });
        const returnTo = `/orgs/${org.login}/sso?authorization_request=${id}`;
        c.header("X-GitHub-SSO", `required; url=${baseUrl}/login/sso?return_to=${encodeURIComponent(returnTo)}`);
      }
      throw error;
    }

    if (context.omittedOrgIds.size > 0) {
      c.header("X-GitHub-SSO", `partial-results; organizations=${[...context.omittedOrgIds].join(",")}`);
    }
  };
}
