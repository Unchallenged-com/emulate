import { describe, expect, it } from "vitest";
import {
  Hono,
  Store,
  WebhookDispatcher,
  authMiddleware,
  setClientAddress,
  type AppEnv,
  type TokenMap,
} from "@emulators/core";
import { googlePlugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";
const directory = "/admin/directory/v1";
const reports = "/admin/reports/v1/activity/users";
const scope = (name: string) => `https://www.googleapis.com/auth/${name}`;
const auditScope = scope("admin.reports.audit.readonly");
const adminScopes = [
  scope("admin.directory.user"),
  scope("admin.directory.user.security"),
  scope("admin.directory.group"),
  auditScope,
].join(" ");
const desktop = { client_id: "it-console", client_secret: "it-secret", name: "IT console" };
const desktopRedirect = "http://127.0.0.1:8080/";
const web = { client_id: "web-app", client_secret: "web-secret", name: "Example portal" };
const webRedirect = "https://portal.example.com/callback";
const admin = "admin@example.com";
const staff = "staff@example.com";
const adminIp = "203.0.113.5";

type Activity = {
  kind: string;
  etag: string;
  id: { time: string; uniqueQualifier: string; applicationName: string; customerId: string };
  actor: { callerType?: string; email: string; profileId: string; applicationInfo?: Record<string, string> };
  ipAddress?: string;
  events: Array<{ type: string; name: string; parameters: Array<Record<string, unknown>> }>;
};
type Report = { kind: string; etag: string; items?: Activity[]; nextPageToken?: string };
type Client = typeof desktop;

function fixture(strict = true) {
  const app = new Hono<AppEnv>();
  const store = new Store();
  const tokens: TokenMap = new Map();
  app.use("*", authMiddleware(tokens, undefined, { login: admin, id: 1, scopes: [] }));
  googlePlugin.register(app, store, new WebhookDispatcher(), base, tokens);
  googlePlugin.seed?.(store, base);
  seedFromConfig(store, base, {
    strict_scopes: strict,
    customer_id: "C0example",
    users: [
      { email: admin, name: "Ada Admin", is_admin: true },
      { email: staff, name: "Sam Staff" },
    ],
    oauth_clients: [
      { ...desktop, redirect_uris: [desktopRedirect] },
      { ...web, redirect_uris: [webRedirect] },
    ],
  });

  // Each request comes from `from`, as the core HTTP listener records a connection's peer.
  function send(path: string, init: RequestInit, from: string) {
    const request = new Request(`${base}${path}`, init);
    setClientAddress(request, from);
    return app.fetch(request);
  }

  function request(path: string, token?: string, method = "GET", body?: unknown, from = adminIp) {
    return send(
      path,
      {
        method,
        headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), "Content-Type": "application/json" },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      },
      from,
    );
  }

  function form(path: string, fields: Record<string, string>, from: string) {
    return send(
      path,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(fields),
      },
      from,
    );
  }

  function signIn(email: string, scopes: string, from = adminIp, client: Client = desktop, redirect = desktopRedirect) {
    return form(
      "/o/oauth2/v2/auth/callback",
      { email, redirect_uri: redirect, scope: scopes, client_id: client.client_id },
      from,
    );
  }

  async function grant(
    email = admin,
    scopes = adminScopes,
    from = adminIp,
    client = desktop,
    redirect = desktopRedirect,
  ) {
    const authorize = await signIn(email, scopes, from, client, redirect);
    expect(authorize.status).toBe(302);
    const code = new URL(authorize.headers.get("Location")!).searchParams.get("code")!;
    const { client_id, client_secret } = client;
    const fields = { client_id, client_secret, grant_type: "authorization_code", code, redirect_uri: redirect };
    const exchange = await form("/oauth2/token", fields, from);
    expect(exchange.status).toBe(200);
    return (await exchange.json()) as { access_token: string; refresh_token: string };
  }

  async function report(auth: string, application: string, query = "", userKey = "all"): Promise<Report> {
    const response = await request(`${reports}/${userKey}/applications/${application}${query}`, auth);
    expect(response.status).toBe(200);
    return (await response.json()) as Report;
  }

  return { request, form, signIn, grant, report };
}

const names = (report: Report) => (report.items ?? []).map((activity) => activity.events[0].name);
const etag = /^"[\w-]+\/[\w-]+"$/;

describe("Google Admin SDK Reports API", () => {
  it("serves its discovery document at the v1 and v2 discovery URLs, rooted at the emulator", async () => {
    const { request } = fixture();
    for (const path of ["/discovery/v1/apis/admin/reports_v1/rest", "/$discovery/rest?version=reports_v1"]) {
      const response = await request(path);
      expect(response.status).toBe(200);
      const doc = (await response.json()) as Record<string, any>;
      expect(doc).toMatchObject({ id: "admin:reports_v1", rootUrl: `${base}/`, servicePath: "" });
      expect(doc.resources.activities.methods.list).toMatchObject({
        httpMethod: "GET",
        path: "admin/reports/v1/activity/users/{userKey}/applications/{applicationName}",
        scopes: [auditScope],
      });
    }
  });

  it("records a sign-in as login_success and the consent as a token authorize event", async () => {
    const { grant, report, request } = fixture();
    const auth = (await grant()).access_token;
    const profileId = ((await (await request(`${directory}/users/${admin}`, auth)).json()) as { id: string }).id;

    const logins = await report(auth, "login");
    expect(logins.kind).toBe("admin#reports#activities");
    expect(logins.etag).toMatch(etag);
    expect(logins.items).toHaveLength(1);
    const [login] = logins.items!;
    expect(login).toMatchObject({
      kind: "admin#reports#activity",
      id: { applicationName: "login", customerId: "C0example" },
      actor: { email: admin, profileId },
      ipAddress: adminIp,
      events: [
        {
          type: "login",
          name: "login_success",
          parameters: [
            { name: "login_type", value: "google_password" },
            { name: "login_challenge_method", multiValue: ["password"] },
            { name: "is_suspicious", boolValue: false },
          ],
        },
      ],
    });
    expect(login.id.time).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
    expect(login.id.uniqueQualifier).toMatch(/^-?\d+$/);
    expect(login.etag).toMatch(etag);
    expect(login.actor).toEqual({ email: admin, profileId });
    expect(login).not.toHaveProperty("ownerDomain");
    // The user the sign-in concerns, as recent records name it.
    const [resource] = (login as Activity & { resourceDetails: Array<Record<string, unknown>> }).resourceDetails;
    expect(resource).toEqual({
      id: expect.stringMatching(/^0[0-9a-v]{13}$/),
      ownerDetails: { ownerIdentity: [{ customerIdentity: { id: "0example" } }], ownerType: "CUSTOMER" },
      title: admin,
      type: "USER",
    });
    expect((login.events[0] as { resourceIds?: string[] }).resourceIds).toEqual([resource.id]);

    const grants = await report(auth, "token");
    expect(grants.items).toHaveLength(1);
    expect(grants.items![0]).toMatchObject({
      id: { applicationName: "token" },
      actor: { email: admin, profileId },
      ipAddress: adminIp,
      events: [
        {
          type: "auth",
          name: "authorize",
          parameters: [
            { name: "client_id", value: desktop.client_id },
            { name: "app_name", value: "IT console" },
            { name: "client_type", value: "NATIVE_DESKTOP" },
            {
              name: "scope_data",
              multiMessageValue: adminScopes.split(" ").map((scope) => ({
                parameter: [
                  { name: "scope_name", value: scope },
                  { name: "product_bucket", multiValue: ["GSUITE_ADMIN"] },
                ],
              })),
            },
            { name: "scope", multiValue: adminScopes.split(" ") },
          ],
        },
      ],
    });
  });

  it("records a suspended user's refused sign-in as login_failure, without a grant", async () => {
    const { grant, request, signIn, report } = fixture();
    const auth = (await grant()).access_token;
    await request(`${directory}/users/${staff}`, auth, "PATCH", { suspended: true });
    expect((await signIn(staff, "openid email", "192.0.2.77")).status).toBe(403);

    const failures = await report(auth, "login", "?eventName=login_failure");
    expect(failures.items).toHaveLength(1);
    expect(failures.items![0]).toMatchObject({
      actor: { email: staff },
      ipAddress: "192.0.2.77",
      events: [
        {
          type: "login",
          name: "login_failure",
          parameters: [
            { name: "login_type", value: "google_password" },
            { name: "login_challenge_method", multiValue: ["password"] },
            { name: "login_failure_type", value: "login_failure_account_disabled" },
          ],
        },
      ],
    });
    expect((await report(auth, "token", "", staff)).items).toBeUndefined();
  });

  it("records a revocation as a token revoke event of the grant's user and client", async () => {
    const { grant, form, report } = fixture();
    const auth = (await grant()).access_token;
    const portal = await grant(staff, "openid email", "192.0.2.40", web, webRedirect);
    expect((await form("/oauth2/revoke", { token: portal.refresh_token }, "192.0.2.41")).status).toBe(200);
    expect((await form("/oauth2/revoke", { token: "never-issued" }, "192.0.2.41")).status).toBe(200);

    const revokes = await report(auth, "token", "?eventName=revoke");
    expect(revokes.items).toHaveLength(1);
    expect(revokes.items![0].actor).toEqual({ email: staff, profileId: expect.any(String) });
    expect(revokes.items![0]).toMatchObject({
      actor: { email: staff },
      ipAddress: "192.0.2.41",
      events: [
        {
          type: "auth",
          name: "revoke",
          parameters: [
            { name: "client_id", value: web.client_id },
            { name: "app_name", value: "Example portal" },
            { name: "client_type", value: "WEB" },
            {
              name: "scope_data",
              multiMessageValue: [
                {
                  parameter: [
                    { name: "scope_name", value: "openid" },
                    { name: "product_bucket", multiValue: ["IDENTITY"] },
                  ],
                },
                {
                  parameter: [
                    { name: "scope_name", value: "email" },
                    { name: "product_bucket", multiValue: ["IDENTITY", "OTHER"] },
                  ],
                },
              ],
            },
            { name: "scope", multiValue: ["openid", "email"] },
          ],
        },
      ],
    });
  });

  it("records the Directory API changes an administrator makes, with the application used", async () => {
    const { grant, request, report } = fixture();
    const auth = (await grant()).access_token;
    const nina = "nina@example.com";
    const user = { primaryEmail: nina, name: { givenName: "Nina", familyName: "Nurse" }, password: "correct-horse-1" };
    await request(`${directory}/users`, auth, "POST", user);
    await request(`${directory}/users/${nina}`, auth, "PATCH", {
      name: { givenName: "Nadia", familyName: "Nurse" },
      password: "correct-horse-2",
      orgUnitPath: "/Nurses",
      changePasswordAtNextLogin: true,
    });
    await request(`${directory}/users/${nina}`, auth, "PATCH", { suspended: true });
    await request(`${directory}/users/${nina}`, auth, "PATCH", { suspended: false });
    await request(`${directory}/users/${nina}/makeAdmin`, auth, "POST", { status: true });
    await request(`${directory}/users/${nina}/makeAdmin`, auth, "POST", { status: true });
    await request(`${directory}/users/${nina}/makeAdmin`, auth, "POST", { status: false });
    await request(`${directory}/groups`, auth, "POST", { email: "nurses@example.com", name: "Nurses" });
    await request(`${directory}/groups/nurses@example.com`, auth, "PATCH", {
      name: "Night nurses",
      description: "x",
    });
    await request(`${directory}/groups/nurses@example.com/members`, auth, "POST", { email: nina });
    await request(`${directory}/groups/nurses@example.com/members/${nina}`, auth, "PATCH", { role: "MANAGER" });
    await request(`${directory}/groups/nurses@example.com/members/${nina}`, auth, "DELETE");
    await request(`${directory}/groups/nurses@example.com`, auth, "DELETE");
    await request(`${directory}/users/${nina}`, auth, "DELETE");
    // Reads and refused changes are not recorded.
    await request(`${directory}/users?customer=my_customer`, auth);
    expect((await request(`${directory}/users`, auth, "POST", { ...user, primaryEmail: staff })).status).toBe(409);

    const changes = await report(auth, "admin");
    // One activity per request, with the events of its changes.
    expect(changes.items!.map((activity) => activity.events.map((e) => e.name)).reverse()).toEqual([
      ["CREATE_USER"],
      ["CHANGE_FIRST_NAME", "CHANGE_PASSWORD", "MOVE_USER_TO_ORG_UNIT", "CHANGE_PASSWORD_ON_NEXT_LOGIN"],
      ["SUSPEND_USER"],
      ["UNSUSPEND_USER"],
      ["GRANT_ADMIN_PRIVILEGE"],
      ["REVOKE_ADMIN_PRIVILEGE"],
      ["CREATE_GROUP"],
      ["CHANGE_GROUP_NAME", "CHANGE_GROUP_DESCRIPTION"],
      ["ADD_GROUP_MEMBER"],
      ["UPDATE_GROUP_MEMBER"],
      ["REMOVE_GROUP_MEMBER"],
      ["DELETE_GROUP"],
      ["DELETE_USER"],
    ]);
    const activity = (name: string) => changes.items!.find((a) => a.events.some((e) => e.name === name))!;
    const event = (name: string) => activity(name).events.find((e) => e.name === name)!;
    expect(activity("CREATE_USER")).toMatchObject({
      id: { applicationName: "admin", customerId: "C0example" },
      actor: {
        callerType: "USER",
        email: admin,
        applicationInfo: { oauthClientId: desktop.client_id, applicationName: "IT console" },
      },
      ipAddress: adminIp,
      events: [{ type: "USER_SETTINGS", name: "CREATE_USER", parameters: [{ name: "USER_EMAIL", value: nina }] }],
    });
    expect(activity("CREATE_USER")).not.toHaveProperty("ownerDomain");
    expect(event("CHANGE_FIRST_NAME").parameters).toEqual([
      { name: "NEW_VALUE", value: "Nadia" },
      { name: "OLD_VALUE", value: "Nina" },
      { name: "USER_EMAIL", value: nina },
    ]);
    expect(event("CHANGE_PASSWORD")).toEqual({
      type: "USER_SETTINGS",
      name: "CHANGE_PASSWORD",
      parameters: [{ name: "USER_EMAIL", value: nina }],
    });
    expect(event("MOVE_USER_TO_ORG_UNIT").parameters).toEqual([
      { name: "NEW_VALUE", value: "/Nurses" },
      { name: "ORG_UNIT_NAME", value: "/" },
      { name: "USER_EMAIL", value: nina },
    ]);
    expect(event("CHANGE_PASSWORD_ON_NEXT_LOGIN").parameters).toEqual([
      { name: "NEW_VALUE", value: "true" },
      { name: "OLD_VALUE", value: "false" },
      { name: "USER_EMAIL", value: nina },
    ]);
    expect(event("GRANT_ADMIN_PRIVILEGE")).toMatchObject({ type: "USER_SETTINGS" });
    expect(event("CHANGE_GROUP_NAME")).toEqual({
      type: "GROUP_SETTINGS",
      name: "CHANGE_GROUP_NAME",
      parameters: [
        { name: "GROUP_EMAIL", value: "nurses@example.com" },
        { name: "NEW_VALUE", value: "Night nurses" },
      ],
    });
    expect(event("ADD_GROUP_MEMBER").parameters).toEqual([
      { name: "USER_EMAIL", value: nina },
      { name: "GROUP_EMAIL", value: "nurses@example.com" },
    ]);
    expect(event("UPDATE_GROUP_MEMBER").parameters).toEqual([
      { name: "GROUP_EMAIL", value: "nurses@example.com" },
      { name: "NEW_VALUE", value: "MANAGER" },
      { name: "OLD_VALUE", value: "MEMBER" },
      { name: "USER_EMAIL", value: nina },
    ]);
    expect(event("REMOVE_GROUP_MEMBER").parameters).toEqual([
      { name: "GROUP_EMAIL", value: "nurses@example.com" },
      { name: "USER_EMAIL", value: nina },
    ]);
  });

  it("records a sign-out and each application's tokens an administrator deletes", async () => {
    const { grant, request, report } = fixture();
    const auth = (await grant()).access_token;
    await grant(staff, "openid email", "192.0.2.40", web, webRedirect);
    await grant(staff, "openid", "192.0.2.40");
    expect((await report(auth, "admin")).items).toBeUndefined();

    expect((await request(`${directory}/users/${staff}/signOut`, auth, "POST")).status).toBe(200);
    for (const client of [web, desktop, { client_id: "never-granted" }]) {
      const deleted = await request(`${directory}/users/${staff}/tokens/${client.client_id}`, auth, "DELETE");
      expect(deleted.status).toBe(200);
    }

    const after = (await report(auth, "admin")).items!.slice(0, 3);
    expect(after.map((a) => a.events)).toEqual([
      [
        {
          type: "USER_SETTINGS",
          name: "REVOKE_3LO_TOKEN",
          parameters: [
            { name: "APP_ID", value: desktop.client_id },
            { name: "USER_EMAIL", value: staff },
          ],
        },
      ],
      [
        {
          type: "USER_SETTINGS",
          name: "REVOKE_3LO_TOKEN",
          parameters: [
            { name: "APP_ID", value: web.client_id },
            { name: "USER_EMAIL", value: staff },
          ],
        },
      ],
      [{ type: "USER_SETTINGS", name: "RESET_SIGNIN_COOKIES", parameters: [{ name: "USER_EMAIL", value: staff }] }],
    ]);
    for (const activity of after) {
      expect(activity.actor).toMatchObject({ callerType: "USER", email: admin });
      expect(activity.ipAddress).toBe(adminIp);
    }
    // The owner's token report gets no revocation of its own.
    expect((await report(auth, "token", "?eventName=revoke", staff)).items).toBeUndefined();
  });

  it("filters by user, event name, parameters, time and address, newest first, in pages", async () => {
    const { grant, request, signIn, report } = fixture();
    const auth = (await grant()).access_token;
    // Activities a few milliseconds apart, on either side of `before`.
    const tick = () => new Promise((resolve) => setTimeout(resolve, 5));
    await tick();
    const before = new Date().toISOString();
    await tick();
    await grant(staff, "openid email", "192.0.2.40", web, webRedirect);
    await request(`${directory}/users/${staff}`, auth, "PATCH", { suspended: true });
    await signIn(staff, "openid email", "192.0.2.66");

    expect(names(await report(auth, "login"))).toEqual(["login_failure", "login_success", "login_success"]);
    const staffLogins = await report(auth, "login", "", staff);
    expect(staffLogins.items!.map((activity) => activity.ipAddress)).toEqual(["192.0.2.66", "192.0.2.40"]);
    expect(staffLogins.items!.every((activity) => activity.actor.email === staff)).toBe(true);
    const staffId = staffLogins.items![0].actor.profileId;
    expect((await report(auth, "login", "", staffId)).items).toHaveLength(2);
    expect(names(await report(auth, "login", "?eventName=login_success"))).toEqual(["login_success", "login_success"]);
    expect((await report(auth, "login", "?actorIpAddress=192.0.2.66")).items).toHaveLength(1);
    expect(names(await report(auth, "admin", "?filters=USER_EMAIL==" + staff))).toEqual(["SUSPEND_USER"]);
    expect((await report(auth, "admin", "?filters=USER_EMAIL%3C%3E" + staff)).items).toBeUndefined();
    expect((await report(auth, "token", "?filters=client_type==WEB")).items).toHaveLength(1);
    expect((await report(auth, "token", "?filters=scope==openid")).items).toHaveLength(1);
    expect((await report(auth, "login", "?eventName=login_success&filters=is_suspicious==true")).items).toBeUndefined();
    expect((await report(auth, "login", "?eventName=login_success&filters=no_such==x")).items).toBeUndefined();
    expect((await report(auth, "login", `?startTime=${encodeURIComponent(before)}`)).items).toHaveLength(2);
    expect((await report(auth, "login", `?endTime=${encodeURIComponent(before)}`)).items).toHaveLength(1);

    const first = await report(auth, "login", "?maxResults=2");
    expect(names(first)).toEqual(["login_failure", "login_success"]);
    expect(first.nextPageToken).toBeTruthy();
    await signIn(admin, "openid", "203.0.113.9");
    const second = await report(auth, "login", `?maxResults=2&pageToken=${first.nextPageToken}`);
    expect(second.items!.map((activity) => activity.actor.email)).toEqual([admin]);
    expect(second).not.toHaveProperty("nextPageToken");

    const empty = await report(auth, "drive");
    expect(empty).toMatchObject({ kind: "admin#reports#activities" });
    expect(empty).not.toHaveProperty("items");
  });

  it("requires a super administrator and the audit scope in strict mode, and refuses what it does not model", async () => {
    const { grant, request } = fixture();
    const auth = (await grant()).access_token;
    const list = `${reports}/all/applications/login`;
    const anonymous = await request(list);
    expect(anonymous.status).toBe(401);
    expect(await anonymous.json()).toMatchObject({ error: { errors: [{ reason: "required" }] } });

    const staffToken = (await grant(staff, auditScope, "192.0.2.40")).access_token;
    const forbidden = await request(list, staffToken);
    expect(forbidden.status).toBe(403);
    expect(await forbidden.json()).toMatchObject({ error: { errors: [{ reason: "forbidden" }] } });
    const directoryOnly = (await grant(admin, scope("admin.directory.user"))).access_token;
    const unscoped = await request(list, directoryOnly);
    expect(unscoped.status).toBe(403);
    expect(await unscoped.json()).toMatchObject({ error: { errors: [{ reason: "insufficientPermissions" }] } });

    const refused = async (path: string, status: number, reason: string) => {
      const response = await request(path, auth);
      expect(response.status).toBe(status);
      expect(await response.json()).toMatchObject({ error: { errors: [{ reason }] } });
    };
    await refused(`${reports}/all/applications/nothing`, 400, "invalid");
    await refused(`${reports}/nobody@example.com/applications/login`, 400, "badRequest");
    await refused(`${list}?customerId=C0other99`, 400, "badRequest");
    await refused(`${list}?orgUnitID=id:abc123`, 400, "badRequest");
    await refused(`${list}?startTime=yesterday`, 400, "invalid");
    await refused(`${list}?startTime=2999-01-01T00:00:00Z`, 400, "invalid");
    await refused(`${list}?startTime=2026-01-02T00:00:00Z&endTime=2026-01-01T00:00:00Z`, 400, "invalid");
    expect((await request(`${list}?customerId=C0example`, auth)).status).toBe(200);
    expect((await request(`${list}?customerId=my_customer`, auth)).status).toBe(200);
  });

  it("keeps the default permissive mode, and records only the account's users", async () => {
    const { request, signIn } = fixture(false);
    expect((await signIn("testuser@gmail.com", "openid")).status).toBe(302);
    expect((await signIn(staff, "openid")).status).toBe(302);
    const response = await request(`${reports}/all/applications/login`, "any-token");
    expect(response.status).toBe(200);
    const body = (await response.json()) as Report;
    expect(body.items!.map((activity) => activity.actor.email)).toEqual([staff]);
  });
});
