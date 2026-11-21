import { describe, expect, it } from "vitest";
import { SignJWT, exportSPKI, generateKeyPair } from "jose";
import { Hono, Store, WebhookDispatcher, authMiddleware, type AppEnv, type TokenMap } from "@emulators/core";
import { googlePlugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";
const admin = "admin@clinic.example";
const account = "directory-sync@clinic-project.iam.gserviceaccount.com";
const accountClientId = "104598730215648392017";
const scope = (name: string) => `https://www.googleapis.com/auth/${name}`;
const scopes = [scope("admin.directory.user"), scope("admin.reports.audit.readonly")];
const gam = { client_id: "it-console", client_secret: "it-secret", redirect: "http://127.0.0.1:8080/" };

type Activity = {
  actor: { callerType?: string; email: string; applicationInfo?: Record<string, unknown> };
  events: Array<{ name: string }>;
};

async function fixture() {
  const pair = await generateKeyPair("RS256");
  const app = new Hono<AppEnv>();
  const store = new Store();
  const tokens: TokenMap = new Map();
  app.use("*", authMiddleware(tokens));
  googlePlugin.register(app, store, new WebhookDispatcher(), base, tokens);
  googlePlugin.seed?.(store, base);
  seedFromConfig(store, base, {
    strict_scopes: true,
    users: [{ email: admin, name: "Ada Admin", is_admin: true }],
    oauth_clients: [{ ...gam, name: "IT console", redirect_uris: [gam.redirect] }],
    service_accounts: [
      {
        client_email: account,
        client_id: accountClientId,
        keys: [{ id: "k1", public_key: await exportSPKI(pair.publicKey) }],
      },
    ],
    domain_wide_delegation: [{ client_id: accountClientId, scopes }],
  });

  const form = (path: string, fields: Record<string, string>) =>
    app.request(`${base}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(fields),
    });

  async function delegatedToken(sub: string) {
    const now = Math.floor(Date.now() / 1000);
    const assertion = await new SignJWT({ scope: scopes.join(" ") })
      .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: "k1" })
      .setIssuer(account)
      .setSubject(sub)
      .setAudience("https://oauth2.googleapis.com/token")
      .setIssuedAt(now)
      .setExpirationTime(now + 3600)
      .sign(pair.privateKey);
    const res = await form("/oauth2/token", { grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion });
    expect(res.status).toBe(200);
    return ((await res.json()) as { access_token: string }).access_token;
  }

  async function userToken() {
    const authorize = await form("/o/oauth2/v2/auth/callback", {
      email: admin,
      redirect_uri: gam.redirect,
      scope: scopes.join(" "),
      client_id: gam.client_id,
    });
    const code = new URL(authorize.headers.get("Location")!).searchParams.get("code")!;
    const exchange = await form("/oauth2/token", {
      client_id: gam.client_id,
      client_secret: gam.client_secret,
      grant_type: "authorization_code",
      code,
      redirect_uri: gam.redirect,
    });
    return ((await exchange.json()) as { access_token: string }).access_token;
  }

  const request = (path: string, token: string, method = "GET", body?: unknown) =>
    app.request(`${base}${path}`, {
      method,
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  return { delegatedToken, userToken, request };
}

const newUser = (email: string) => ({
  primaryEmail: email,
  name: { givenName: "New", familyName: "User" },
  password: "Secret-pass-123",
});

describe("Google Reports API delegated actors", () => {
  it("names the service account and the impersonation on an administrator change made with domain-wide delegation", async () => {
    const { delegatedToken, request } = await fixture();
    const token = await delegatedToken(admin);
    expect((await request("/admin/directory/v1/users", token, "POST", newUser("new@clinic.example"))).status).toBe(200);

    const response = await request("/admin/reports/v1/activity/users/all/applications/admin", token);
    expect(response.status).toBe(200);
    const [activity] = ((await response.json()) as { items: Activity[] }).items;
    expect(activity.events[0].name).toBe("CREATE_USER");
    expect(activity.actor).toMatchObject({ callerType: "USER", email: admin });
    expect(activity.actor.applicationInfo).toEqual({ oauthClientId: accountClientId, impersonation: true });
  });

  it("keeps an administrator's own change through an OAuth client without impersonation", async () => {
    const { userToken, request } = await fixture();
    const token = await userToken();
    expect((await request("/admin/directory/v1/users", token, "POST", newUser("own@clinic.example"))).status).toBe(200);

    const response = await request("/admin/reports/v1/activity/users/all/applications/admin", token);
    const [activity] = ((await response.json()) as { items: Activity[] }).items;
    expect(activity.actor.applicationInfo).toEqual({ oauthClientId: gam.client_id, applicationName: "IT console" });
  });
});
