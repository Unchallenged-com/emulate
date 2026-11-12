import { describe, expect, it } from "vitest";
import { Hono, Store, WebhookDispatcher, authMiddleware, type AppEnv, type TokenMap } from "@emulators/core";
import { googlePlugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";
const scope = (name: string) => `https://www.googleapis.com/auth/${name}`;
const client = { client_id: "settings-client", client_secret: "settings-secret" };
const redirectUri = "http://127.0.0.1:8080/";
const admin = "admin@clinic.example";
const staff = "staff@clinic.example";
const group = "nurses@clinic.example";
const settingsPath = `/groups/v1/groups/${group}?alt=json`;

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

  const request = (path: string, token?: string, method = "GET", body?: unknown) =>
    app.request(`${base}${path}`, {
      method,
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });

  async function token(email: string, scopes: string): Promise<string> {
    const form = (path: string, body: Record<string, string>) =>
      app.request(`${base}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(body),
      });
    const authorize = await form("/o/oauth2/v2/auth/callback", {
      email,
      redirect_uri: redirectUri,
      scope: scopes,
      client_id: client.client_id,
    });
    const code = new URL(authorize.headers.get("Location")!).searchParams.get("code")!;
    const exchange = await form("/oauth2/token", {
      ...client,
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
    });
    return ((await exchange.json()) as { access_token: string }).access_token;
  }

  async function adminToken(): Promise<string> {
    const auth = await token(admin, [scope("admin.directory.group"), scope("apps.groups.settings")].join(" "));
    await request("/admin/directory/v1/groups", auth, "POST", { email: group });
    return auth;
  }

  return { request, token, adminToken };
}

describe("Google Groups Settings API", () => {
  it("serves its discovery document, rooted at the emulator", async () => {
    const { request } = fixture();
    const doc = (await (await request("/discovery/v1/apis/groupssettings/v1/rest")).json()) as Record<string, any>;
    expect(doc).toMatchObject({ id: "groupssettings:v1", rootUrl: `${base}/`, servicePath: "groups/v1/groups/" });
    expect(Object.keys(doc.resources.groups.methods).sort()).toEqual(["get", "patch", "update"]);
  });

  it("sets a group's name and description, shared with the Directory API", async () => {
    const { request, adminToken } = fixture();
    const auth = await adminToken();
    const updated = await request(settingsPath, auth, "PUT", { name: "Nurses", description: "Nursing staff" });
    expect(updated.status).toBe(200);
    expect(await updated.json()).toMatchObject({
      kind: "groupsSettings#groups",
      email: group,
      name: "Nurses",
      description: "Nursing staff",
      spamModerationLevel: "MODERATE",
      messageDisplayFont: "DEFAULT_FONT",
    });
    const directory = await request(`/admin/directory/v1/groups/${group}`, auth);
    expect(await directory.json()).toMatchObject({ name: "Nurses", description: "Nursing staff" });
  });

  it("keeps settings across patches and validates documented values and rules", async () => {
    const { request, adminToken } = fixture();
    const auth = await adminToken();
    await request(settingsPath, auth, "PATCH", { whoCanJoin: "INVITED_CAN_JOIN", allowExternalMembers: "false" });
    const patched = await request(settingsPath, auth, "PATCH", { whoCanViewMembership: "ALL_MANAGERS_CAN_VIEW" });
    expect(await patched.json()).toMatchObject({
      whoCanJoin: "INVITED_CAN_JOIN",
      whoCanViewMembership: "ALL_MANAGERS_CAN_VIEW",
      allowExternalMembers: "false",
    });

    const ignored = await request(settingsPath, auth, "PATCH", {
      whoCanAddExternalMembers: "END_USERS_CAN_ADD_EXTERNAL_MEMBERS",
      customRolesEnabledForSettingsToBeMerged: "true",
      email: "other@clinic.example",
    });
    const body = (await ignored.json()) as Record<string, unknown>;
    expect(body).not.toHaveProperty("whoCanAddExternalMembers");
    expect(body).not.toHaveProperty("customRolesEnabledForSettingsToBeMerged");
    expect(body.email).toBe(group);

    for (const settings of [
      { whoCanJoin: "EVERYONE" },
      { name: "N".repeat(76) },
      { description: "D".repeat(301) },
      { whoCanPostMessage: "NONE_CAN_POST" },
      { replyTo: "REPLY_TO_CUSTOM" },
      { notASetting: "true" },
    ]) {
      const refused = await request(settingsPath, auth, "PATCH", settings);
      expect(refused.status, JSON.stringify(settings)).toBe(400);
      expect(await refused.json()).toMatchObject({ error: { errors: [{ reason: "invalid" }] } });
    }
    const archived = await request(settingsPath, auth, "PATCH", {
      archiveOnly: "true",
      whoCanPostMessage: "NONE_CAN_POST",
    });
    expect(archived.status).toBe(200);
    const custom = await request(settingsPath, auth, "PATCH", {
      replyTo: "REPLY_TO_CUSTOM",
      customReplyTo: "help@clinic.example",
    });
    expect(custom.status).toBe(200);
  });

  it("names the group by its email address only", async () => {
    const { request, adminToken } = fixture();
    const auth = await adminToken();
    const id = ((await (await request(`/admin/directory/v1/groups/${group}`, auth)).json()) as { id: string }).id;
    expect((await request(`/groups/v1/groups/${id}?alt=json`, auth)).status).toBe(404);
    expect((await request(`/groups/v1/groups/NURSES@clinic.example?alt=json`, auth)).status).toBe(200);
    expect((await request(`/groups/v1/groups/${group}`, auth)).status).toBe(400);
  });

  it("requires a super administrator and the apps.groups.settings scope in strict mode", async () => {
    const { request, token, adminToken } = fixture();
    await adminToken();
    expect((await request(settingsPath)).status).toBe(401);
    const staffToken = await token(staff, scope("apps.groups.settings"));
    expect((await request(settingsPath, staffToken)).status).toBe(403);
    const directoryOnly = await token(admin, scope("admin.directory.group"));
    const denied = await request(settingsPath, directoryOnly);
    expect(denied.status).toBe(403);
    expect(await denied.json()).toMatchObject({ error: { errors: [{ reason: "insufficientPermissions" }] } });
  });
});
