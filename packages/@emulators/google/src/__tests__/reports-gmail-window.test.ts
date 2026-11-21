import { describe, expect, it } from "vitest";
import { Hono, Store, WebhookDispatcher, authMiddleware, type AppEnv, type TokenMap } from "@emulators/core";
import { googlePlugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";
const reports = "/admin/reports/v1/activity/users/all/applications";
const admin = "admin@example.com";
const client = { client_id: "it-console", client_secret: "it-secret", name: "IT console" };
const redirect = "http://127.0.0.1:8080/";

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
    oauth_clients: [{ ...client, redirect_uris: [redirect] }],
  });

  const form = (path: string, fields: Record<string, string>) =>
    app.request(path, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(fields),
    });
  const scope = "https://www.googleapis.com/auth/admin.reports.audit.readonly";
  const authorize = await form("/o/oauth2/v2/auth/callback", {
    email: admin,
    redirect_uri: redirect,
    scope,
    client_id: client.client_id,
  });
  const code = new URL(authorize.headers.get("Location")!).searchParams.get("code")!;
  const exchange = await form("/oauth2/token", {
    client_id: client.client_id,
    client_secret: client.client_secret,
    grant_type: "authorization_code",
    code,
    redirect_uri: redirect,
  });
  const { access_token } = (await exchange.json()) as { access_token: string };
  return (application: string, query = "") =>
    app.request(`${reports}/${application}${query}`, { headers: { Authorization: `Bearer ${access_token}` } });
}

const iso = (ms: number) => encodeURIComponent(new Date(ms).toISOString());
const day = 24 * 60 * 60 * 1000;

describe("Google Reports API Gmail time window", () => {
  it("requires both startTime and endTime for Gmail, at most 30 days apart", async () => {
    const list = await fixture();
    const now = Date.now();
    for (const query of [
      "",
      `?startTime=${iso(now - day)}`,
      `?endTime=${iso(now)}`,
      `?startTime=${iso(now - 31 * day)}&endTime=${iso(now)}`,
    ]) {
      const response = await list("gmail", query);
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ error: { code: 400, errors: [{ reason: "invalid" }] } });
    }
    for (const query of [
      `?startTime=${iso(now - 30 * day)}&endTime=${iso(now)}`,
      `?startTime=${iso(now - day)}&endTime=${iso(now)}`,
    ]) {
      const response = await list("gmail", query);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({ kind: "admin#reports#activities" });
    }
  });

  it("keeps the other applications' bounds optional", async () => {
    const list = await fixture();
    for (const application of ["login", "admin", "token", "drive"]) {
      expect((await list(application)).status).toBe(200);
    }
    const now = Date.now();
    expect((await list("login", `?startTime=${iso(now - 60 * day)}&endTime=${iso(now)}`)).status).toBe(200);
  });
});
