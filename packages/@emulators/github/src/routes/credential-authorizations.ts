import type { AppEnv, Context, RouteContext } from "@emulators/core";
import { ApiError, parseJsonBody, parsePagination, setLinkHeader, unauthorized } from "@emulators/core";
import { getGitHubStore } from "../store.js";
import type { GitHubCredentialAuthorization, GitHubCredentialKind } from "../entities.js";
import { credentialHash } from "../saml-credentials.js";
import { requireOrgAdmin } from "./orgs.js";

// GitHub Enterprise Cloud: "Credential authorizations" for an organization that uses SAML SSO.

const REVOCATION_WARNING =
  "The token used for this request may also have its authorization revoked as part of this operation";
const CREDENTIAL_TYPES = ["classic_pat", "fine_grained_pat", "ssh_key", "oauth_app_token"] as const;
type RevocableCredentialType = (typeof CREDENTIAL_TYPES)[number];

export function credentialAuthorizationsRoutes({ app, store, tokenMap }: RouteContext): void {
  const gh = getGitHubStore(store);

  /** A token seeded as authorized has no login recorded: read it, and its scopes, from the token map. */
  function tokenOwner(row: GitHubCredentialAuthorization): { login: string | null; scopes: string[] } {
    if (row.login !== null) return { login: row.login, scopes: row.scopes ?? [] };
    for (const [token, user] of tokenMap ?? []) {
      if (credentialHash(token) === row.credential_hash)
        return { login: user.login, scopes: row.scopes ?? user.scopes };
    }
    return { login: null, scopes: row.scopes ?? [] };
  }

  function formatCredentialAuthorization(row: GitHubCredentialAuthorization) {
    const owner = tokenOwner(row);
    return {
      login: owner.login,
      credential_id: row.id,
      credential_type: row.credential_kind === "oauth_app_token" ? "OAuth app token" : "personal access token",
      token_last_eight: row.token_last_eight,
      credential_authorized_at: row.created_at,
      scopes: owner.scopes,
      credential_accessed_at: row.credential_accessed_at,
      authorized_credential_id: row.authorized_credential_id,
      authorized_credential_note: null,
      authorized_credential_expires_at: null,
    };
  }

  function ownerOnly(c: Context<AppEnv>) {
    const authUser = c.get("authUser");
    if (!authUser) throw unauthorized();
    const org = gh.orgs.findOneBy("login", c.req.param("org")!);
    if (!org) throw new ApiError(404, "Not Found");
    requireOrgAdmin(gh, org, authUser);
    return org;
  }

  /** Revokes the matching authorizations at once, and warns when the request's own token is among them. */
  function revoke(
    c: Context<AppEnv>,
    orgId: number,
    matches: (row: GitHubCredentialAuthorization) => boolean,
    message: string,
  ) {
    const callerHash = credentialHash(c.get("authToken") ?? "");
    let revokedCaller = false;
    for (const row of gh.credentialAuthorizations.findBy("org_id", orgId).filter(matches)) {
      if (row.credential_hash === callerHash) revokedCaller = true;
      gh.credentialAuthorizations.delete(row.id);
    }
    return c.json(revokedCaller ? { message, warning: REVOCATION_WARNING } : { message }, 202);
  }

  async function credentialTypeFromBody(c: Context<AppEnv>) {
    const body = await parseJsonBody(c);
    const type = body.credential_type;
    if (typeof type !== "string" || !(CREDENTIAL_TYPES as readonly string[]).includes(type)) {
      throw new ApiError(
        422,
        "The `credential_type` parameter is required and must be one of: classic_pat, fine_grained_pat, ssh_key, oauth_app_token",
      );
    }
    return type as RevocableCredentialType;
  }

  function ofType(type: RevocableCredentialType) {
    // SSH keys are not emulated, so revoking them matches no authorization.
    return (row: GitHubCredentialAuthorization) => row.credential_kind === (type as GitHubCredentialKind);
  }

  function forUser(c: Context<AppEnv>) {
    const username = c.req.param("username")!;
    const user = gh.users.findOneBy("login", username);
    if (!user) throw new ApiError(404, "Not Found");
    return user.login;
  }

  app.get("/orgs/:org/credential-authorizations", (c) => {
    const org = ownerOnly(c);
    const login = c.req.query("login");
    const rows = gh.credentialAuthorizations
      .findBy("org_id", org.id)
      .sort((a, b) => a.id - b.id)
      .map(formatCredentialAuthorization)
      .filter((row) => login === undefined || row.login === login);
    const { page, per_page } = parsePagination(c);
    setLinkHeader(c, rows.length, page, per_page);
    return c.json(rows.slice((page - 1) * per_page, page * per_page));
  });

  app.post("/orgs/:org/credential-authorizations/revoke-all", (c) => {
    const org = ownerOnly(c);
    return revoke(c, org.id, () => true, "Credential authorization revocation has been queued");
  });

  app.post("/orgs/:org/credential-authorizations/revoke-credential-type", async (c) => {
    const org = ownerOnly(c);
    const type = await credentialTypeFromBody(c);
    return revoke(c, org.id, ofType(type), "Credential type revocation has been queued");
  });

  app.post("/orgs/:org/credential-authorizations/:username/revoke", (c) => {
    const org = ownerOnly(c);
    const login = forUser(c);
    return revoke(
      c,
      org.id,
      (row) => tokenOwner(row).login === login,
      `Credential authorization revocation for user '${login}' has been queued`,
    );
  });

  app.post("/orgs/:org/credential-authorizations/:username/revoke-credential-type", async (c) => {
    const org = ownerOnly(c);
    const login = forUser(c);
    const type = await credentialTypeFromBody(c);
    const matchesType = ofType(type);
    return revoke(
      c,
      org.id,
      (row) => matchesType(row) && tokenOwner(row).login === login,
      `Credential type revocation for user '${login}' has been queued`,
    );
  });

  app.delete("/orgs/:org/credential-authorizations/:credential_id", (c) => {
    const org = ownerOnly(c);
    const id = Number(c.req.param("credential_id"));
    const row = Number.isInteger(id) ? gh.credentialAuthorizations.get(id) : undefined;
    if (!row || row.org_id !== org.id) throw new ApiError(404, "Not Found");
    gh.credentialAuthorizations.delete(row.id);
    return c.body(null, 204);
  });
}
