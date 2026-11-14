import { describe, expect, it } from "vitest";
import { Hono, Store, WebhookDispatcher, authMiddleware, type AppEnv, type TokenMap } from "@emulators/core";
import { googlePlugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";
const directory = "/admin/directory/v1";
const scope = (name: string) => `https://www.googleapis.com/auth/${name}`;
const security = scope("admin.directory.user.security");
const client = { client_id: "sign-out-client", client_secret: "sign-out-secret" };
const redirectUri = "http://127.0.0.1:8080/";
const admin = "admin@clinic.example";
const staff = "staff@clinic.example";

function fixture() {
  const app = new Hono<AppEnv>();
  const store = new Store();
  const tokens: TokenMap = new Map();
  app.use("*", authMiddleware(tokens, undefined, { login: admin, id: 1, scopes: [] }));
  googlePlugin.register(app, store, new WebhookDispatcher(), base, tokens);
  googlePlugin.seed?.(store, base);
  seedFromConfig(store, base, {
    strict_scopes: true,
    users: [
      { email: admin, name: "Ada Admin", is_admin: true },
      { email: staff, name: "Sam Staff" },
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

  const request = (path: string, token: string, method = "GET") =>
    app.request(`${base}${path}`, { method, headers: { Authorization: `Bearer ${token}` } });
  const refresh = (token: string) =>
    form("/oauth2/token", { ...client, grant_type: "refresh_token", refresh_token: token });

  return { app, grant, request, refresh };
}

describe("Google Directory API users.signOut", () => {
  it("signs a user out and keeps the tokens they issued to applications", async () => {
    const { grant, request, refresh } = fixture();
    const auth = (await grant(admin, [security])).access_token;
    const issued = await grant(staff, ["openid", "email"]);

    for (const key of [staff, staff.toUpperCase()]) {
      const response = await request(`${directory}/users/${key}/signOut`, auth, "POST");
      expect(response.status).toBe(200);
      expect(await response.text()).toBe("");
    }

    expect((await request("/oauth2/v2/userinfo", issued.access_token)).status).toBe(200);
    expect((await refresh(issued.refresh_token)).status).toBe(200);
  });

  it("answers for unknown users as the other user methods do", async () => {
    const { grant, request } = fixture();
    const auth = (await grant(admin, [security])).access_token;
    const response = await request(`${directory}/users/nobody@clinic.example/signOut`, auth, "POST");
    expect(response.status).toBe(404);
    expect(await response.json()).toMatchObject({
      error: { message: "Resource Not Found: userKey", errors: [{ reason: "notFound" }] },
    });
  });

  it("requires the user security scope and a super administrator", async () => {
    const { grant, request } = fixture();
    const withoutScope = (await grant(admin, [scope("admin.directory.user")])).access_token;
    const denied = await request(`${directory}/users/${staff}/signOut`, withoutScope, "POST");
    expect(denied.status).toBe(403);
    expect(await denied.json()).toMatchObject({ error: { errors: [{ reason: "insufficientPermissions" }] } });

    const nonAdmin = (await grant(staff, [security])).access_token;
    const forbidden = await request(`${directory}/users/${admin}/signOut`, nonAdmin, "POST");
    expect(forbidden.status).toBe(403);
    expect(await forbidden.json()).toMatchObject({ error: { errors: [{ reason: "forbidden" }] } });
  });

  it("describes users.signOut in the discovery document", async () => {
    const { app } = fixture();
    const doc = (await (await app.request(`${base}/discovery/v1/apis/admin/directory_v1/rest`)).json()) as any;
    expect(doc.resources.users.methods.signOut).toMatchObject({
      httpMethod: "POST",
      path: "admin/directory/v1/users/{userKey}/signOut",
      scopes: [security],
    });
    expect(doc.auth.oauth2.scopes[security]).toBeDefined();
  });
});
