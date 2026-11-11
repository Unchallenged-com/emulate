import { describe, it, expect } from "vitest";
import { createServer, type AppKeyResolver, type Hono } from "@emulators/core";
import { createAppKeyResolver, githubPlugin, seedFromConfig } from "../index.js";
import { base, buildResponse, consume, idpKey, idpUrl, signIn, startSso } from "./saml-fixtures.js";

const OWNER_PAT = "ghp_owner_token_1234ABCD";
const MEMBER_PAT = "ghp_member_token_5678EFGH";
const PAT_MESSAGE =
  "Resource protected by organization SAML enforcement. You must grant your Personal Access token access to this organization.";

interface CredentialAuthorization {
  login: string;
  credential_id: number;
  credential_type: string;
  token_last_eight: string;
  credential_authorized_at: string;
  scopes: string[];
  credential_accessed_at: string | null;
  authorized_credential_id: number;
  authorized_credential_note: string | null;
  authorized_credential_expires_at: string | null;
}

function createTestApp() {
  // Built the way the CLI builds it: seeded tokens, an App key resolver over the store, and a fallback user.
  const keys: { resolve?: AppKeyResolver } = {};
  const { app, store } = createServer(githubPlugin, {
    baseUrl: base,
    tokens: {
      [OWNER_PAT]: { login: "octocat", id: 3, scopes: ["admin:org", "repo"] },
      [MEMBER_PAT]: { login: "hubot", id: 4, scopes: ["repo"] },
    },
    appKeyResolver: (appId) => keys.resolve!(appId),
    fallbackUser: { login: "octocat", id: 3, scopes: ["repo", "user", "admin:org", "admin:repo_hook"] },
  });
  keys.resolve = createAppKeyResolver(store);
  githubPlugin.seed?.(store, base);
  seedFromConfig(store, base, {
    users: [{ login: "octocat" }, { login: "hubot" }],
    orgs: [
      {
        login: "acme",
        members: [{ login: "octocat", role: "admin" }, { login: "hubot" }],
        saml: {
          sign_on_url: idpUrl,
          public_certificate: idpKey.certificate,
          enforced: true,
          authorized_tokens: [OWNER_PAT, MEMBER_PAT],
        },
      },
    ],
    repos: [{ owner: "acme", name: "secret", private: true }],
  });
  return { app, store };
}

function api(app: Hono, path: string, token: string, init: RequestInit = {}) {
  return app.request(`${base}${path}`, {
    ...init,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...(init.headers ?? {}) },
  });
}

async function list(app: Hono, query = ""): Promise<CredentialAuthorization[]> {
  const res = await api(app, `/orgs/acme/credential-authorizations${query}`, OWNER_PAT);
  expect(res.status).toBe(200);
  return (await res.json()) as CredentialAuthorization[];
}

/** An OAuth token for hubot, authorized for acme by authorizing the app during a SAML session. */
async function memberOAuthToken(app: Hono): Promise<string> {
  const sessionId = await signIn(app, "hubot");
  const { requestId } = await startSso(app, sessionId);
  expect((await consume(app, sessionId, buildResponse({ requestId, nameId: "hubot@acme.test" }))).status).toBe(302);
  const callback = await app.request(`${base}/login/oauth/callback`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: `_emu_session=${sessionId}` },
    body: new URLSearchParams({
      login: "hubot",
      redirect_uri: "http://localhost:3000/cb",
      client_id: "client",
      scope: "repo read:org",
    }),
  });
  const code = new URL(callback.headers.get("Location")!).searchParams.get("code")!;
  const res = await app.request(`${base}/login/oauth/access_token`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ client_id: "client", client_secret: "secret", code }),
  });
  return ((await res.json()) as { access_token: string }).access_token;
}

describe("GitHub organization credential authorizations", () => {
  it("lists the organization's authorizations for an owner with the documented fields", async () => {
    const { app } = createTestApp();
    const oauthToken = await memberOAuthToken(app);
    expect((await api(app, "/repos/acme/secret", MEMBER_PAT)).status).toBe(200);

    const rows = await list(app);
    expect(rows.map((row) => [row.login, row.credential_type])).toEqual([
      ["octocat", "personal access token"],
      ["hubot", "personal access token"],
      ["hubot", "OAuth app token"],
    ]);

    const [owner, member, oauth] = rows;
    expect(owner).toEqual({
      login: "octocat",
      credential_id: expect.any(Number),
      credential_type: "personal access token",
      token_last_eight: "1234ABCD",
      credential_authorized_at: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
      scopes: ["admin:org", "repo"],
      credential_accessed_at: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
      authorized_credential_id: expect.any(Number),
      authorized_credential_note: null,
      authorized_credential_expires_at: null,
    });
    expect(member.token_last_eight).toBe("5678EFGH");
    expect(member.credential_accessed_at).not.toBeNull();
    expect(oauth.token_last_eight).toBe(oauthToken.slice(-8));
    expect(oauth.scopes).toEqual(["repo", "read:org"]);
    expect(oauth.credential_accessed_at).toBeNull();
    expect(new Set(rows.map((row) => row.credential_id)).size).toBe(3);
    expect(new Set(rows.map((row) => row.authorized_credential_id)).size).toBe(3);

    expect((await list(app, "?login=hubot")).map((row) => row.credential_id)).toEqual([
      member.credential_id,
      oauth.credential_id,
    ]);
  });

  it("paginates with per_page and page", async () => {
    const { app } = createTestApp();
    const res = await api(app, "/orgs/acme/credential-authorizations?per_page=1&page=2", OWNER_PAT);
    expect(res.status).toBe(200);
    expect(((await res.json()) as CredentialAuthorization[]).map((row) => row.login)).toEqual(["hubot"]);
    expect(res.headers.get("Link")).toContain('rel="first"');
  });

  it("refuses a member who is not an owner", async () => {
    const { app } = createTestApp();
    expect((await api(app, "/orgs/acme/credential-authorizations", MEMBER_PAT)).status).toBe(403);
    const [member] = await list(app, "?login=hubot");
    const res = await api(app, `/orgs/acme/credential-authorizations/${member.credential_id}`, MEMBER_PAT, {
      method: "DELETE",
    });
    expect(res.status).toBe(403);
    expect((await api(app, "/repos/acme/secret", MEMBER_PAT)).status).toBe(200);
  });

  it("removes an authorization, after which the credential needs SAML SSO authorization again", async () => {
    const { app } = createTestApp();
    const [member] = await list(app, "?login=hubot");
    const res = await api(app, `/orgs/acme/credential-authorizations/${member.credential_id}`, OWNER_PAT, {
      method: "DELETE",
    });
    expect(res.status).toBe(204);

    const refused = await api(app, "/repos/acme/secret", MEMBER_PAT);
    expect(refused.status).toBe(403);
    expect(((await refused.json()) as { message: string }).message).toBe(PAT_MESSAGE);
    expect(refused.headers.get("X-GitHub-SSO")).toMatch(/^required; url=/);
    expect((await list(app)).map((row) => row.login)).toEqual(["octocat"]);
  });

  it("returns 404 when removing an unknown authorization", async () => {
    const { app } = createTestApp();
    const res = await api(app, "/orgs/acme/credential-authorizations/999999", OWNER_PAT, { method: "DELETE" });
    expect(res.status).toBe(404);
    expect((await list(app)).length).toBe(2);
  });

  it("revokes every authorization, warning that the caller's token is among them", async () => {
    const { app } = createTestApp();
    const res = await api(app, "/orgs/acme/credential-authorizations/revoke-all", OWNER_PAT, { method: "POST" });
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({
      message: "Credential authorization revocation has been queued",
      warning: "The token used for this request may also have its authorization revoked as part of this operation",
    });
    expect((await api(app, "/repos/acme/secret", MEMBER_PAT)).status).toBe(403);
    expect((await api(app, "/orgs/acme/credential-authorizations", OWNER_PAT)).status).toBe(403);
  });

  it("revokes a single credential type across the organization", async () => {
    const { app } = createTestApp();
    const oauthToken = await memberOAuthToken(app);

    const invalid = await api(app, "/orgs/acme/credential-authorizations/revoke-credential-type", OWNER_PAT, {
      method: "POST",
      body: JSON.stringify({ credential_type: "password" }),
    });
    expect(invalid.status).toBe(422);
    expect(((await invalid.json()) as { message: string }).message).toBe(
      "The `credential_type` parameter is required and must be one of: classic_pat, fine_grained_pat, ssh_key, oauth_app_token",
    );

    const res = await api(app, "/orgs/acme/credential-authorizations/revoke-credential-type", OWNER_PAT, {
      method: "POST",
      body: JSON.stringify({ credential_type: "oauth_app_token" }),
    });
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ message: "Credential type revocation has been queued" });
    expect((await api(app, "/repos/acme/secret", oauthToken)).status).toBe(403);
    expect((await api(app, "/repos/acme/secret", MEMBER_PAT)).status).toBe(200);
  });

  it("revokes one user's authorizations, or one credential type for that user", async () => {
    const { app } = createTestApp();
    const oauthToken = await memberOAuthToken(app);

    const byType = await api(app, "/orgs/acme/credential-authorizations/hubot/revoke-credential-type", OWNER_PAT, {
      method: "POST",
      body: JSON.stringify({ credential_type: "classic_pat" }),
    });
    expect(byType.status).toBe(202);
    expect(await byType.json()).toEqual({ message: "Credential type revocation for user 'hubot' has been queued" });
    expect((await api(app, "/repos/acme/secret", MEMBER_PAT)).status).toBe(403);
    expect((await api(app, "/repos/acme/secret", oauthToken)).status).toBe(200);

    const all = await api(app, "/orgs/acme/credential-authorizations/hubot/revoke", OWNER_PAT, { method: "POST" });
    expect(all.status).toBe(202);
    expect(await all.json()).toEqual({
      message: "Credential authorization revocation for user 'hubot' has been queued",
    });
    expect((await api(app, "/repos/acme/secret", oauthToken)).status).toBe(403);
    expect((await list(app)).map((row) => row.login)).toEqual(["octocat"]);

    const unknown = await api(app, "/orgs/acme/credential-authorizations/nobody/revoke", OWNER_PAT, { method: "POST" });
    expect(unknown.status).toBe(404);
  });
});
