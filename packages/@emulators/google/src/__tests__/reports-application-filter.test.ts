import { describe, expect, it } from "vitest";
import { Hono, Store, WebhookDispatcher, authMiddleware, type AppEnv, type TokenMap } from "@emulators/core";
import { googlePlugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";
const reports = "/admin/reports/v1/activity/users/all/applications";
const admin = "admin@example.com";
const scopes = ["admin.directory.user", "admin.reports.audit.readonly"]
  .map((name) => `https://www.googleapis.com/auth/${name}`)
  .join(" ");
const console_ = { client_id: "it-console", client_secret: "it-secret", redirect: "http://127.0.0.1:8080/" };
const portal = { client_id: "web-app", client_secret: "web-secret", redirect: "https://portal.example.com/callback" };

async function fixture() {
  const app = new Hono<AppEnv>();
  const store = new Store();
  const tokens: TokenMap = new Map();
  app.use("*", authMiddleware(tokens, undefined, { login: admin, id: 1, scopes: [] }));
  googlePlugin.register(app, store, new WebhookDispatcher(), base, tokens);
  googlePlugin.seed?.(store, base);
  seedFromConfig(store, base, {
    strict_scopes: true,
    users: [{ email: admin, name: "Ada Admin", is_admin: true }],
    oauth_clients: [
      {
        client_id: console_.client_id,
        client_secret: console_.client_secret,
        name: "IT console",
        redirect_uris: [console_.redirect],
      },
      {
        client_id: portal.client_id,
        client_secret: portal.client_secret,
        name: "Portal",
        redirect_uris: [portal.redirect],
      },
    ],
  });

  const form = (path: string, fields: Record<string, string>) =>
    app.request(path, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(fields),
    });
  async function grant(client: typeof console_) {
    const authorize = await form("/o/oauth2/v2/auth/callback", {
      email: admin,
      redirect_uri: client.redirect,
      scope: scopes,
      client_id: client.client_id,
    });
    const code = new URL(authorize.headers.get("Location")!).searchParams.get("code")!;
    const exchange = await form("/oauth2/token", {
      client_id: client.client_id,
      client_secret: client.client_secret,
      grant_type: "authorization_code",
      code,
      redirect_uri: client.redirect,
    });
    return ((await exchange.json()) as { access_token: string }).access_token;
  }
  const request = (path: string, token: string, method = "GET", body?: unknown) =>
    app.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  return { grant, request };
}

type Report = {
  items?: Array<{ actor: { applicationInfo?: { oauthClientId: string } }; events: Array<{ name: string }> }>;
};

describe("Google Reports API applicationInfoFilter", () => {
  it("lists only the activities of the application with the given OAuth client ID", async () => {
    const { grant, request } = await fixture();
    const fromConsole = await grant(console_);
    const fromPortal = await grant(portal);
    const user = {
      primaryEmail: "new@example.com",
      name: { givenName: "New", familyName: "User" },
      password: "Secret-pass-123",
    };
    expect((await request("/admin/directory/v1/users", fromConsole, "POST", user)).status).toBe(200);
    expect((await request("/admin/directory/v1/users/new@example.com", fromPortal, "DELETE")).status).toBe(200);

    const list = async (filter: string) => {
      const response = await request(
        `${reports}/admin?applicationInfoFilter=${encodeURIComponent(filter)}`,
        fromConsole,
      );
      expect(response.status).toBe(200);
      return (await response.json()) as Report;
    };
    const byConsole = await list(`oAuthClientId="${console_.client_id}"`);
    expect(byConsole.items?.map((activity) => activity.events[0].name)).toEqual(["CREATE_USER"]);
    expect(byConsole.items?.[0].actor.applicationInfo?.oauthClientId).toBe(console_.client_id);
    const byPortal = await list(`oAuthClientId="${portal.client_id}"`);
    expect(byPortal.items?.map((activity) => activity.events[0].name)).toEqual(["DELETE_USER"]);
    expect((await list('oAuthClientId="unknown-client"')).items).toBeUndefined();
    // AIP-160 allows spaces around the comparison operator.
    const spaced = await list(`oAuthClientId = "${console_.client_id}"`);
    expect(spaced.items?.map((activity) => activity.events[0].name)).toEqual(["CREATE_USER"]);
    const malformed = await request(`${reports}/admin?applicationInfoFilter=${console_.client_id}`, fromConsole);
    expect(malformed.status).toBe(400);
    // Sign-ins carry no application: the filter leaves none of them.
    const logins = await request(
      `${reports}/login?applicationInfoFilter=${encodeURIComponent(`oAuthClientId="${console_.client_id}"`)}`,
      fromConsole,
    );
    expect(((await logins.json()) as Report).items).toBeUndefined();
  });
});
