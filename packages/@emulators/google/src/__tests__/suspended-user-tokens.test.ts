import { describe, expect, it } from "vitest";
import { Hono, Store, WebhookDispatcher, authMiddleware, type AppEnv, type TokenMap } from "@emulators/core";
import { googlePlugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";
const directory = "/admin/directory/v1";
const scope = (name: string) => `https://www.googleapis.com/auth/${name}`;
const client = { client_id: "suspension-client", client_secret: "suspension-secret" };
const redirectUri = "http://127.0.0.1:8080/";
const admin = "admin@clinic.example";
const staff = "staff@clinic.example";
const colleague = "colleague@clinic.example";
const staffScopes = ["openid", "email", "https://mail.google.com/", scope("drive")];

function fixture(strict?: boolean) {
  const app = new Hono<AppEnv>();
  const store = new Store();
  const tokens: TokenMap = new Map();
  app.use("*", authMiddleware(tokens, undefined, { login: admin, id: 1, scopes: [] }));
  googlePlugin.register(app, store, new WebhookDispatcher(), base, tokens);
  googlePlugin.seed?.(store, base);
  seedFromConfig(store, base, {
    ...(strict === undefined ? {} : { strict_scopes: strict }),
    users: [
      { email: admin, name: "Ada Admin", is_admin: true },
      { email: staff, name: "Sam Staff" },
      { email: colleague, name: "Cleo Colleague" },
    ],
    oauth_clients: [{ ...client, redirect_uris: [redirectUri] }],
  });

  const form = (path: string, body: Record<string, string>) =>
    app.request(`${base}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body).toString(),
    });

  async function grant(email: string, scopes: string[]) {
    const authorize = await form("/o/oauth2/v2/auth/callback", {
      email,
      redirect_uri: redirectUri,
      scope: scopes.join(" "),
      client_id: client.client_id,
    });
    const code = new URL(authorize.headers.get("Location")!).searchParams.get("code")!;
    const exchange = await form("/oauth2/token", {
      ...client,
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
    });
    expect(exchange.status).toBe(200);
    return (await exchange.json()) as { access_token: string; refresh_token: string };
  }

  const request = (path: string, token: string, method = "GET", body?: unknown) =>
    app.request(`${base}${path}`, {
      method,
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  const refresh = (token: string) =>
    form("/oauth2/token", { ...client, grant_type: "refresh_token", refresh_token: token });

  async function setSuspended(email: string, suspended: boolean) {
    const auth = (await grant(admin, [scope("admin.directory.user")])).access_token;
    expect((await request(`${directory}/users/${email}`, auth, "PATCH", { suspended })).status).toBe(200);
  }

  return { grant, request, refresh, setSuspended };
}

const resources = ["/oauth2/v2/userinfo", "/gmail/v1/users/me/messages", "/drive/v3/files"];

describe("Google tokens of a suspended user in strict mode", () => {
  it("refuses the access tokens issued before the suspension", async () => {
    const { grant, request, setSuspended } = fixture(true);
    const issued = await grant(staff, staffScopes);
    const unaffected = await grant(colleague, staffScopes);
    for (const path of resources) expect((await request(path, issued.access_token)).status).toBe(200);

    await setSuspended(staff, true);

    for (const path of resources) {
      const response = await request(path, issued.access_token);
      expect(response.status, path).toBe(401);
      expect(await response.json()).toMatchObject({ error: { code: 401, status: "UNAUTHENTICATED" } });
      expect((await request(path, unaffected.access_token)).status, path).toBe(200);
    }
  });

  it("refuses a suspended administrator's Directory calls with the Directory API's error", async () => {
    const { grant, request, setSuspended } = fixture(true);
    const own = (await grant(admin, [scope("admin.directory.user")])).access_token;
    await setSuspended(admin, true);
    const response = await request(`${directory}/users/${staff}`, own);
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ error: { code: 401, errors: [{ reason: "authError" }] } });
  });

  it("refuses the refresh tokens issued before the suspension", async () => {
    const { grant, refresh, setSuspended } = fixture(true);
    const issued = await grant(staff, staffScopes);
    await setSuspended(staff, true);
    const response = await refresh(issued.refresh_token);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_grant" });
  });

  it("accepts the same tokens again once the user is restored", async () => {
    const { grant, request, refresh, setSuspended } = fixture(true);
    const issued = await grant(staff, staffScopes);
    await setSuspended(staff, true);
    await setSuspended(staff, false);
    for (const path of resources) expect((await request(path, issued.access_token)).status).toBe(200);
    expect((await refresh(issued.refresh_token)).status).toBe(200);
  });
});

describe.each([undefined, false])(
  "Google tokens of a suspended user in permissive mode (strict_scopes=%s)",
  (strict) => {
    it("keeps accepting access tokens and refuses refresh tokens", async () => {
      const { grant, request, refresh, setSuspended } = fixture(strict);
      const issued = await grant(staff, staffScopes);
      await setSuspended(staff, true);
      for (const path of resources) expect((await request(path, issued.access_token)).status).toBe(200);
      expect((await refresh(issued.refresh_token)).status).toBe(400);
    });
  },
);
