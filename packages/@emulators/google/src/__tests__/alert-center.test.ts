import { describe, expect, it } from "vitest";
import { Hono, Store, WebhookDispatcher, authMiddleware, type AppEnv, type TokenMap } from "@emulators/core";
import { googlePlugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";
const admin = "admin@example.com";
const other = "root@example.com";
const staff = "staff@example.com";
const scope = (name: string) => `https://www.googleapis.com/auth/${name}`;
const alertsScope = scope("apps.alerts");
const client = { client_id: "it-console", client_secret: "it-secret", redirect: "http://127.0.0.1:8080/" };

type Alert = {
  customerId: string;
  alertId: string;
  createTime: string;
  startTime: string;
  updateTime: string;
  type: string;
  source: string;
  data: Record<string, unknown>;
  deleted?: boolean;
  metadata: Record<string, unknown>;
  etag: string;
};

async function fixture(rules?: string[]) {
  const app = new Hono<AppEnv>();
  const store = new Store();
  const tokens: TokenMap = new Map();
  app.use("*", authMiddleware(tokens, undefined, { login: admin, id: 1, scopes: [] }));
  googlePlugin.register(app, store, new WebhookDispatcher(), base, tokens);
  googlePlugin.seed?.(store, base);
  seedFromConfig(store, base, {
    strict_scopes: true,
    customer_id: "C0example",
    ...(rules ? { alert_rules: rules } : {}),
    users: [
      { email: admin, name: "Ada Admin", is_admin: true },
      { email: other, name: "Root Admin", is_admin: true },
      { email: staff, name: "Sam Staff" },
    ],
    oauth_clients: [{ ...client, name: "IT console", redirect_uris: [client.redirect] }],
  });

  const form = (path: string, fields: Record<string, string>) =>
    app.request(`${base}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(fields),
    });
  async function grant(email: string, scopes: string[]) {
    const authorize = await form("/o/oauth2/v2/auth/callback", {
      email,
      redirect_uri: client.redirect,
      scope: scopes.join(" "),
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
  const token = await grant(admin, [scope("admin.directory.user"), alertsScope]);
  const request = (path: string, method = "GET", body?: unknown, auth = token) =>
    app.request(`${base}${path}`, {
      method,
      headers: { Authorization: `Bearer ${auth}`, "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  async function alerts(query = ""): Promise<Alert[]> {
    const response = await request(`/v1beta1/alerts${query}`);
    expect(response.status).toBe(200);
    return ((await response.json()) as { alerts?: Alert[] }).alerts ?? [];
  }
  return { grant, request, alerts };
}

const newUser = (email: string) => ({
  primaryEmail: email,
  name: { givenName: "New", familyName: "User" },
  password: "Secret-pass-123",
});

describe("Google Alert Center API", () => {
  it("raises the User Changes alerts whose rules are on, with Google's types and the rule name", async () => {
    const { request, alerts } = await fixture(["New user added", "User granted Admin privilege", "User deleted"]);
    expect((await request("/admin/directory/v1/users", "POST", newUser("new@example.com"))).status).toBe(200);
    expect(
      (await request("/admin/directory/v1/users/new@example.com/makeAdmin", "POST", { status: true })).status,
    ).toBe(200);
    // Suspension's rule is off: no alert.
    expect((await request("/admin/directory/v1/users/new@example.com", "PATCH", { suspended: true })).status).toBe(200);

    const listed = await alerts("?orderBy=create_time%20asc");
    expect(listed.map((alert) => [alert.source, alert.type, alert.data])).toEqual([
      [
        "User Changes",
        "New user Added",
        { "@type": "type.googleapis.com/google.apps.alertcenter.type.UserChanges", name: "New user added" },
      ],
      [
        "User Changes",
        "User granted Admin privilege",
        {
          "@type": "type.googleapis.com/google.apps.alertcenter.type.UserChanges",
          name: "User granted Admin privilege",
        },
      ],
    ]);
    const [first] = listed;
    expect(first.alertId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(first.customerId).toBe("0example");
    expect(first).not.toHaveProperty("deleted");
    expect(first.metadata).toMatchObject({
      customerId: "0example",
      alertId: first.alertId,
      status: "NOT_STARTED",
      severity: "",
    });
    expect(first.startTime).toBe(first.createTime);
  });

  it("raises Super admin password reset when a super administrator's password changes, with no rule to turn on", async () => {
    const { request, alerts } = await fixture();
    expect(
      (await request(`/admin/directory/v1/users/${other}`, "PATCH", { password: "Another-pass-456" })).status,
    ).toBe(200);
    expect(
      (await request(`/admin/directory/v1/users/${staff}`, "PATCH", { password: "Another-pass-456" })).status,
    ).toBe(200);
    const [alert, ...rest] = await alerts();
    expect(rest).toEqual([]);
    expect(alert).toMatchObject({
      source: "Sensitive Admin Action",
      type: "Super admin password reset",
      data: {
        "@type": "type.googleapis.com/google.apps.alertcenter.type.SensitiveAdminAction",
        actorEmail: admin,
        superAdminPasswordResetEvent: { userEmail: other },
      },
    });
    expect(Date.parse(alert.data.eventTime as string)).not.toBeNaN();
  });

  it("gets, filters, pages, deletes and restores alerts", async () => {
    const { request, alerts } = await fixture(["New user added"]);
    for (const email of ["a@example.com", "b@example.com", "c@example.com"]) {
      await request("/admin/directory/v1/users", "POST", newUser(email));
    }
    const all = await alerts();
    expect(all).toHaveLength(3);
    const [newest] = all;

    const got = await request(`/v1beta1/alerts/${newest.alertId}`);
    expect(await got.json()).toEqual(newest);
    expect(await (await request(`/v1beta1/alerts/${newest.alertId}/metadata`)).json()).toEqual(newest.metadata);
    expect((await request("/v1beta1/alerts/nope")).status).toBe(404);

    expect(
      await alerts(`?filter=${encodeURIComponent('type:"New user Added" AND source:"User Changes"')}`),
    ).toHaveLength(3);
    expect(await alerts(`?filter=${encodeURIComponent('type:"User deleted"')}`)).toEqual([]);
    expect(await alerts(`?filter=${encodeURIComponent(`createTime>="${newest.createTime}"`)}`)).not.toEqual([]);
    expect((await request(`/v1beta1/alerts?filter=${encodeURIComponent("bogus=1")}`)).status).toBe(400);

    const page = (await (await request("/v1beta1/alerts?pageSize=2")).json()) as {
      alerts: Alert[];
      nextPageToken: string;
    };
    expect(page.alerts).toHaveLength(2);
    const rest = (await (await request(`/v1beta1/alerts?pageSize=2&pageToken=${page.nextPageToken}`)).json()) as {
      alerts: Alert[];
      nextPageToken?: string;
    };
    expect(rest.alerts).toHaveLength(1);
    expect(rest.nextPageToken).toBeUndefined();

    expect((await request(`/v1beta1/alerts/${newest.alertId}`, "DELETE")).status).toBe(200);
    expect(await alerts()).toHaveLength(2);
    expect(((await (await request(`/v1beta1/alerts/${newest.alertId}`)).json()) as Alert).deleted).toBe(true);
    expect((await request("/v1beta1/alerts/nope", "DELETE")).status).toBe(404);
    const restored = await request(`/v1beta1/alerts/${newest.alertId}:undelete`, "POST", {});
    expect(restored.status).toBe(200);
    expect((await restored.json()) as Alert).not.toHaveProperty("deleted");

    const batch = await request("/v1beta1/alerts:batchDelete", "POST", { alertId: [all[1].alertId, "nope"] });
    expect(await batch.json()).toEqual({
      successAlertIds: [all[1].alertId],
      failedAlertStatus: { nope: { code: 5, message: "Requested entity was not found." } },
    });
    expect(await alerts()).toHaveLength(2);
    const undone = await request("/v1beta1/alerts:batchUndelete", "POST", { alertId: [all[1].alertId] });
    expect(await undone.json()).toEqual({ successAlertIds: [all[1].alertId] });
    expect(await alerts()).toHaveLength(3);
  });

  it("takes feedback on an alert, and keeps the customer's notification settings", async () => {
    const { request, alerts } = await fixture(["New user added"]);
    await request("/admin/directory/v1/users", "POST", newUser("new@example.com"));
    const [alert] = await alerts();
    const created = await request(`/v1beta1/alerts/${alert.alertId}/feedback`, "POST", { type: "VERY_USEFUL" });
    expect(created.status).toBe(200);
    const feedback = await created.json();
    expect(feedback).toMatchObject({
      customerId: "0example",
      alertId: alert.alertId,
      type: "VERY_USEFUL",
      email: admin,
    });
    expect(await (await request(`/v1beta1/alerts/${alert.alertId}/feedback`)).json()).toEqual({ feedback: [feedback] });
    expect((await request(`/v1beta1/alerts/${alert.alertId}/feedback`, "POST", { type: "BOGUS" })).status).toBe(400);

    await request(`/v1beta1/alerts/${alert.alertId}`, "DELETE");
    const refused = await request(`/v1beta1/alerts/${alert.alertId}/feedback`, "POST", { type: "NOT_USEFUL" });
    expect(refused.status).toBe(400);
    expect(await refused.json()).toMatchObject({ error: { status: "FAILED_PRECONDITION" } });

    const notifications = [{ cloudPubsubTopic: { topicName: "projects/p/topics/alerts", payloadFormat: "JSON" } }];
    expect(await (await request("/v1beta1/settings", "PATCH", { notifications })).json()).toEqual({ notifications });
    expect(await (await request("/v1beta1/settings")).json()).toEqual({ notifications });
  });

  it("is for super administrators with the apps.alerts scope, and refuses unknown rules in the seed", async () => {
    const { grant, request } = await fixture();
    const staffToken = await grant(staff, [alertsScope]);
    expect((await request("/v1beta1/alerts", "GET", undefined, staffToken)).status).toBe(403);
    const unscoped = await grant(admin, [scope("admin.directory.user")]);
    expect((await request("/v1beta1/alerts", "GET", undefined, unscoped)).status).toBe(403);
    expect((await request("/v1beta1/alerts?customerId=0other")).status).toBe(400);
    expect((await request("/v1beta1/alerts?customerId=0example")).status).toBe(200);
    await expect(fixture(["No such rule"])).rejects.toThrow(/unknown rule/);
  });
});
