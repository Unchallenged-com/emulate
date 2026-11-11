import { generateKeyPairSync, sign } from "crypto";
import { describe, it, expect, afterEach, vi } from "vitest";
import { createServer, type AppKeyResolver, type Hono, type Store } from "@emulators/core";
import { createAppKeyResolver, getGitHubStore, githubPlugin, seedFromConfig } from "../index.js";
import { base, buildResponse, consume, hiddenField, idpKey, idpUrl, signIn, startSso } from "./saml-fixtures.js";

const PAT = "ghp_octocat_token";
const AUTHORIZED_PAT = "ghp_octocat_authorized";
const OUTSIDER_PAT = "ghp_outsider_token";
const PAT_MESSAGE =
  "Resource protected by organization SAML enforcement. You must grant your Personal Access token access to this organization.";
const OAUTH_MESSAGE =
  "Resource protected by organization SAML enforcement. You must grant your OAuth token access to this organization.";

const { privateKey: appPrivateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs1", format: "pem" },
  publicKeyEncoding: { type: "pkcs1", format: "pem" },
});

function createTestApp(options: { enforced?: boolean } = {}) {
  // Built the way the CLI builds it: seeded tokens, an App key resolver over the store, and a fallback user.
  const keys: { resolve?: AppKeyResolver } = {};
  const { app, store } = createServer(githubPlugin, {
    baseUrl: base,
    tokens: {
      [PAT]: { login: "octocat", id: 3 },
      [AUTHORIZED_PAT]: { login: "octocat", id: 3 },
      [OUTSIDER_PAT]: { login: "outsider", id: 4 },
    },
    appKeyResolver: (appId) => keys.resolve!(appId),
    fallbackUser: { login: "octocat", id: 3, scopes: ["repo", "user", "admin:org", "admin:repo_hook"] },
  });
  keys.resolve = createAppKeyResolver(store);
  githubPlugin.seed?.(store, base);
  seedFromConfig(store, base, {
    users: [{ login: "octocat" }, { login: "outsider" }],
    orgs: [
      {
        login: "acme",
        members: [{ login: "octocat", role: "admin" }],
        saml: {
          sign_on_url: idpUrl,
          public_certificate: idpKey.certificate,
          enforced: options.enforced ?? true,
          authorized_tokens: [AUTHORIZED_PAT],
        },
      },
      { login: "plain", members: [{ login: "octocat" }] },
    ],
    repos: [
      { owner: "acme", name: "secret", private: true },
      { owner: "plain", name: "secret", private: true },
    ],
    apps: [
      {
        app_id: 42,
        slug: "acme-app",
        name: "Acme App",
        private_key: appPrivateKey,
        permissions: { contents: "read", metadata: "read" },
        installations: [{ installation_id: 100, account: "acme" }],
      },
    ],
  });
  return { app, store };
}

function api(app: Hono, path: string, token: string, init: RequestInit = {}) {
  return app.request(`${base}${path}`, {
    ...init,
    headers: { Authorization: `Bearer ${token}`, ...(init.headers ?? {}) },
  });
}

function ssoUrl(res: Response): URL {
  const header = res.headers.get("X-GitHub-SSO") ?? "";
  // Read the URL the way GitHub's CLI does.
  const match = /\burl=([^;]+)/.exec(header);
  expect(header.startsWith("required; ")).toBe(true);
  expect(match).not.toBeNull();
  return new URL(match![1]);
}

function cookie(sessionId: string) {
  return { Cookie: `_emu_session=${sessionId}` };
}

/** Opens a SAML session for acme in the browser session. */
async function samlSignIn(app: Hono, sessionId: string) {
  const { requestId } = await startSso(app, sessionId);
  expect((await consume(app, sessionId, buildResponse({ requestId }))).status).toBe(302);
}

/** Follows the X-GitHub-SSO URL in a signed-in browser with a SAML session and returns the authorization page. */
async function authorizationPage(app: Hono, sessionId: string, url: URL) {
  const login = await app.request(url.toString(), { headers: cookie(sessionId) });
  expect(login.status).toBe(302);
  return app.request(`${base}${login.headers.get("Location")}`, { headers: cookie(sessionId) });
}

async function oauthToken(app: Hono, sessionId: string | null): Promise<string> {
  const callback = await app.request(`${base}/login/oauth/callback`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...(sessionId ? cookie(sessionId) : {}) },
    body: new URLSearchParams({ login: "octocat", redirect_uri: "http://localhost:3000/cb", client_id: "client" }),
  });
  const code = new URL(callback.headers.get("Location")!).searchParams.get("code")!;
  const res = await app.request(`${base}/login/oauth/access_token`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ client_id: "client", client_secret: "secret", code }),
  });
  return ((await res.json()) as { access_token: string }).access_token;
}

function acmeId(store: Store) {
  return getGitHubStore(store).orgs.findOneBy("login", "acme")!.id;
}

describe("GitHub organization SAML SSO for personal access tokens", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("refuses an unauthorized token on the organization's private repository with GitHub's message and header", async () => {
    const { app } = createTestApp();
    const res = await api(app, "/repos/acme/secret", PAT);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { message: string }).message).toBe(PAT_MESSAGE);

    const url = ssoUrl(res);
    expect(`${url.origin}${url.pathname}`).toBe(`${base}/login/sso`);
    expect(url.searchParams.get("return_to")).toMatch(/^\/orgs\/acme\/sso\?authorization_request=[0-9a-f]+$/);
  });

  it("refuses organization endpoints that membership grants", async () => {
    const { app } = createTestApp();
    const create = await api(app, "/orgs/acme/repos", PAT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "new-repo" }),
    });
    expect(create.status).toBe(403);
    expect(ssoUrl(create).pathname).toBe("/login/sso");

    const update = await api(app, "/orgs/acme", PAT, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ description: "changed" }),
    });
    expect(update.status).toBe(403);
    expect(((await update.json()) as { message: string }).message).toBe(PAT_MESSAGE);
  });

  it("sends the authorization page through the identity provider without a SAML session", async () => {
    const { app } = createTestApp();
    const url = ssoUrl(await api(app, "/repos/acme/secret", PAT));

    const anonymous = await app.request(url.toString());
    expect(anonymous.status).toBe(200);
    expect(hiddenField(await anonymous.text(), "redirect_uri")).toBe(url.toString());

    const sessionId = await signIn(app, "octocat");
    const page = await authorizationPage(app, sessionId, url);
    const html = await page.text();
    expect(html).toContain(`action="${idpUrl}"`);
    expect(hiddenField(html, "RelayState")).toBe(url.searchParams.get("return_to"));
  });

  it("accepts the token once the user authorizes it with a SAML session", async () => {
    const { app } = createTestApp();
    const url = ssoUrl(await api(app, "/repos/acme/secret", PAT));
    const sessionId = await signIn(app, "octocat");

    const { requestId } = await startSso(
      app,
      sessionId,
      `?return_to=${encodeURIComponent(url.searchParams.get("return_to")!)}`,
    );
    const consumed = await consume(app, sessionId, buildResponse({ requestId }), url.searchParams.get("return_to")!);
    expect(consumed.headers.get("Location")).toBe(url.searchParams.get("return_to"));

    const page = await authorizationPage(app, sessionId, url);
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain('action="/orgs/acme/sso"');
    expect((await api(app, "/repos/acme/secret", PAT)).status).toBe(403);

    const confirm = await app.request(`${base}/orgs/acme/sso`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", ...cookie(sessionId) },
      body: new URLSearchParams({ authorization_request: hiddenField(html, "authorization_request")! }),
    });
    expect(confirm.status).toBe(302);

    const res = await api(app, "/repos/acme/secret", PAT);
    expect(res.status).toBe(200);
    expect(res.headers.get("X-GitHub-SSO")).toBeNull();
  });

  it("expires the authorization URL after one hour", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
    const { app } = createTestApp();
    const url = ssoUrl(await api(app, "/repos/acme/secret", PAT));
    const sessionId = await signIn(app, "octocat");
    await samlSignIn(app, sessionId);

    vi.setSystemTime(new Date("2026-01-01T00:59:59Z"));
    expect((await authorizationPage(app, sessionId, url)).status).toBe(200);

    vi.setSystemTime(new Date("2026-01-01T01:00:00Z"));
    expect((await authorizationPage(app, sessionId, url)).status).toBe(404);
    const confirm = await app.request(`${base}/orgs/acme/sso`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", ...cookie(sessionId) },
      body: new URLSearchParams({
        authorization_request: new URLSearchParams(url.searchParams.get("return_to")!.split("?")[1]).get(
          "authorization_request",
        )!,
      }),
    });
    expect(confirm.status).toBe(404);
    expect((await api(app, "/repos/acme/secret", PAT)).status).toBe(403);
  });

  it("accepts a token seeded as authorized", async () => {
    const { app } = createTestApp();
    expect((await api(app, "/repos/acme/secret", AUTHORIZED_PAT)).status).toBe(200);
    expect((await api(app, "/repos/acme/secret", PAT)).status).toBe(403);
  });

  it("requires authorization for a member with a linked identity even when SAML is not enforced", async () => {
    const { app } = createTestApp({ enforced: false });
    expect((await api(app, "/repos/acme/secret", PAT)).status).toBe(200);

    const sessionId = await signIn(app, "octocat");
    await samlSignIn(app, sessionId);

    const res = await api(app, "/repos/acme/secret", PAT);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { message: string }).message).toBe(PAT_MESSAGE);
  });

  it("leaves organizations without SAML and users outside the organization as they were", async () => {
    const { app } = createTestApp();
    expect((await api(app, "/repos/acme/secret", PAT)).status).toBe(403);
    expect((await api(app, "/repos/plain/secret", PAT)).status).toBe(200);

    const outsider = await api(app, "/repos/acme/secret", OUTSIDER_PAT);
    expect(outsider.status).toBe(403);
    expect(((await outsider.json()) as { message: string }).message).toBe("Forbidden");
    expect(outsider.headers.get("X-GitHub-SSO")).toBeNull();
  });

  it("leaves results out of lists and names the organizations in a partial-results header", async () => {
    const { app, store } = createTestApp();
    const res = await api(app, "/search/repositories?q=secret", PAT);
    expect(res.status).toBe(200);
    const names = ((await res.json()) as { items: Array<{ full_name: string }> }).items.map((r) => r.full_name);
    expect(names).toEqual(["plain/secret"]);
    expect(res.headers.get("X-GitHub-SSO")).toBe(`partial-results; organizations=${acmeId(store)}`);
  });
});

describe("GitHub organization SAML SSO for app tokens", () => {
  it("refuses an OAuth token without an authorization URL, since only reauthorizing the app helps", async () => {
    const { app } = createTestApp();
    const token = await oauthToken(app, null);
    const res = await api(app, "/repos/acme/secret", token);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { message: string }).message).toBe(OAUTH_MESSAGE);
    expect(res.headers.get("X-GitHub-SSO")).toBeNull();

    const search = await api(app, "/search/repositories?q=secret", token);
    const names = ((await search.json()) as { items: Array<{ full_name: string }> }).items.map((r) => r.full_name);
    expect(names).toEqual(["plain/secret"]);
    expect(search.headers.get("X-GitHub-SSO")).toBeNull();
  });

  it("authorizes the token of an app the user authorizes again during a SAML session", async () => {
    const { app } = createTestApp();
    const sessionId = await signIn(app, "octocat");
    const before = await oauthToken(app, sessionId);
    const refused = await api(app, "/repos/acme/secret", before);
    expect(refused.status).toBe(403);
    expect(refused.headers.get("X-GitHub-SSO")).toBeNull();

    await samlSignIn(app, sessionId);
    const after = await oauthToken(app, sessionId);
    expect(after.startsWith("gho_")).toBe(true);
    expect((await api(app, "/repos/acme/secret", after)).status).toBe(200);
    expect((await api(app, "/repos/acme/secret", before)).status).toBe(403);
  });

  it("does not require authorization for an installation token", async () => {
    const { app } = createTestApp();
    const now = Math.floor(Date.now() / 1000);
    const unsigned = [
      { alg: "RS256", typ: "JWT" },
      { iat: now - 60, exp: now + 540, iss: "42" },
    ]
      .map((part) => Buffer.from(JSON.stringify(part)).toString("base64url"))
      .join(".");
    const jwt = `${unsigned}.${sign("RSA-SHA256", Buffer.from(unsigned), appPrivateKey).toString("base64url")}`;
    const minted = await api(app, "/app/installations/100/access_tokens", jwt, { method: "POST" });
    expect(minted.status).toBe(201);
    const { token } = (await minted.json()) as { token: string };

    const res = await api(app, "/repos/acme/secret", token);
    expect(res.status).toBe(200);
    expect(res.headers.get("X-GitHub-SSO")).toBeNull();
    expect((await api(app, "/repos/acme/secret", PAT)).status).toBe(403);
  });
});
