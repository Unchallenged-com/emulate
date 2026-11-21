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
const reports = "/admin/reports/v1/activity/users";
const scope = (name: string) => `https://www.googleapis.com/auth/${name}`;
const adminScopes = [scope("admin.directory.user"), scope("admin.reports.audit.readonly")].join(" ");
const mailScopes = [scope("gmail.readonly"), scope("drive.readonly"), scope("calendar.readonly")].join(" ");
const itConsole = { client_id: "it-console", client_secret: "it-secret", name: "IT console" };
const consoleRedirect = "http://127.0.0.1:8080/";
const reader = { client_id: "mail-reader", client_secret: "reader-secret", name: "Mail reader" };
const readerRedirect = "https://reader.example.net/callback";
const admin = "admin@example.com";
const staff = "staff@example.com";
const adminIp = "203.0.113.5";
const appIp = "198.51.100.66";

type Parameter = { name: string; value?: string; intValue?: string };
type Activity = {
  actor: { email: string; profileId: string };
  ipAddress?: string;
  events: Array<{ type: string; name: string; parameters: Parameter[] }>;
};
type Client = typeof itConsole;

function fixture(strict = true) {
  const app = new Hono<AppEnv>();
  const store = new Store();
  const tokens: TokenMap = new Map();
  app.use("*", authMiddleware(tokens, undefined, { login: admin, id: 1, scopes: [] }));
  googlePlugin.register(app, store, new WebhookDispatcher(), base, tokens);
  googlePlugin.seed?.(store, base);
  seedFromConfig(store, base, {
    strict_scopes: strict,
    users: [
      { email: admin, name: "Ada Admin", is_admin: true },
      { email: staff, name: "Sam Staff" },
    ],
    oauth_clients: [
      { ...itConsole, redirect_uris: [consoleRedirect] },
      { ...reader, redirect_uris: [readerRedirect] },
    ],
  });

  function send(path: string, init: RequestInit, from: string) {
    const request = new Request(`${base}${path}`, init);
    setClientAddress(request, from);
    return app.fetch(request);
  }

  function request(path: string, token: string, from: string, method = "GET") {
    return send(path, { method, headers: { Authorization: `Bearer ${token}` } }, from);
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

  async function grant(email: string, scopes: string, from: string, client: Client, redirect: string) {
    const fields = { email, redirect_uri: redirect, scope: scopes, client_id: client.client_id };
    const authorize = await form("/o/oauth2/v2/auth/callback", fields, from);
    expect(authorize.status).toBe(302);
    const code = new URL(authorize.headers.get("Location")!).searchParams.get("code")!;
    const { client_id, client_secret } = client;
    const exchange = await form(
      "/oauth2/token",
      { client_id, client_secret, grant_type: "authorization_code", code, redirect_uri: redirect },
      from,
    );
    expect(exchange.status).toBe(200);
    return ((await exchange.json()) as { access_token: string }).access_token;
  }

  const adminToken = () => grant(admin, adminScopes, adminIp, itConsole, consoleRedirect);
  const readerToken = () => grant(staff, mailScopes, appIp, reader, readerRedirect);

  /** The `activity` events of the token application, oldest first. */
  async function activities(auth: string, query = ""): Promise<Activity[]> {
    const response = await request(`${reports}/all/applications/token?eventName=activity${query}`, auth, adminIp);
    expect(response.status).toBe(200);
    return (((await response.json()) as { items?: Activity[] }).items ?? []).reverse();
  }

  return { request, grant, adminToken, readerToken, activities };
}

const parameter = (activity: Activity, name: string) => activity.events[0].parameters.find((p) => p.name === name);

describe("Google Reports API token activity", () => {
  it("records an application's API call as a token activity event with Google's parameters", async () => {
    const { request, adminToken, readerToken, activities } = fixture();
    const auth = await readerToken();
    const listed = await request("/gmail/v1/users/me/messages", auth, appIp);
    expect(listed.status).toBe(200);
    const bytes = (await listed.arrayBuffer()).byteLength;

    const [activity] = await activities(await adminToken());
    expect(activity).toMatchObject({
      actor: { email: staff },
      ipAddress: appIp,
      events: [
        {
          type: "auth",
          name: "activity",
          parameters: [
            { name: "api_name", value: "gmail" },
            { name: "method_name", value: "gmail.users.messages.list" },
            { name: "client_id", value: reader.client_id },
            { name: "num_response_bytes", intValue: String(bytes) },
            { name: "product_bucket", value: "GMAIL" },
            { name: "app_name", value: "Mail reader" },
            { name: "client_type", value: "WEB" },
          ],
        },
      ],
    });
    expect(activity.events[0].parameters).toHaveLength(7);
  });

  it("names each emulated API by its discovery document and the method by its discovery ID", async () => {
    const { request, adminToken, readerToken, activities } = fixture();
    const auth = await readerToken();
    for (const path of ["/drive/v3/files", "/calendar/v3/calendars/primary/events", "/gmail/v1/users/me/labels"]) {
      expect((await request(path, auth, appIp)).status).toBe(200);
    }
    const admin = await adminToken();
    expect((await request(`/admin/directory/v1/users/${staff}`, admin, adminIp)).status).toBe(200);

    const seen = (await activities(admin)).map((activity) => [
      parameter(activity, "api_name")?.value,
      parameter(activity, "method_name")?.value,
      parameter(activity, "product_bucket")?.value,
    ]);
    expect(seen).toEqual([
      ["drive", "drive.files.list", "DRIVE"],
      ["calendar", "calendar.events.list", "CALENDAR"],
      ["gmail", "gmail.users.labels.list", "GMAIL"],
      ["admin", "directory.users.get", "GSUITE_ADMIN"],
    ]);
  });

  it("records the Reports API's own calls, as Google's records show", async () => {
    const { adminToken, activities } = fixture();
    const auth = await adminToken();
    await activities(auth);
    const [first] = await activities(auth);
    expect(first.actor.email).toBe(admin);
    expect(parameter(first, "api_name")?.value).toBe("admin");
    expect(parameter(first, "method_name")?.value).toBe("reports.activities.list");
    expect(parameter(first, "product_bucket")?.value).toBe("GSUITE_ADMIN");
    expect(parameter(first, "client_type")?.value).toBe("NATIVE_DESKTOP");
  });

  it("filters activity events by method name and by the application's client", async () => {
    const { request, adminToken, readerToken, activities } = fixture();
    const auth = await readerToken();
    await request("/gmail/v1/users/me/messages", auth, appIp);
    await request("/drive/v3/files", auth, appIp);

    const admin = await adminToken();
    const drive = await activities(admin, "&filters=method_name==drive.files.list");
    expect(drive).toHaveLength(1);
    expect(parameter(drive[0], "api_name")?.value).toBe("drive");
    const fromReader = await activities(admin, `&filters=client_id==${reader.client_id}`);
    expect(fromReader.map((activity) => parameter(activity, "method_name")?.value)).toEqual([
      "gmail.users.messages.list",
      "drive.files.list",
    ]);
  });

  it("records nothing for a refused call, an unknown token, or a call without a token", async () => {
    const { request, adminToken, readerToken, activities } = fixture();
    const auth = await readerToken();
    // gmail.readonly, drive.readonly and calendar.readonly do not cover the Directory API.
    expect((await request(`/admin/directory/v1/users/${staff}`, auth, appIp)).status).toBe(403);
    expect((await request("/gmail/v1/users/me/messages", "not-a-token", appIp)).status).toBe(401);
    expect((await request("/gmail/v1/users/me/messages", "", appIp)).status).toBe(401);
    expect(await activities(await adminToken())).toEqual([]);
  });

  it("records calls outside strict mode too, for tokens the emulator issued from a grant", async () => {
    const { request, adminToken, readerToken, activities } = fixture(false);
    const auth = await readerToken();
    expect((await request("/gmail/v1/users/me/messages", auth, appIp)).status).toBe(200);
    const [activity] = await activities(await adminToken());
    expect(activity.actor.email).toBe(staff);
    expect(parameter(activity, "method_name")?.value).toBe("gmail.users.messages.list");
  });
});
