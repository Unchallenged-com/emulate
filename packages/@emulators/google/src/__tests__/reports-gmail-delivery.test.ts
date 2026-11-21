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
const gmailReport = "/admin/reports/v1/activity/users/all/applications/gmail";
const admin = "admin@example.com";
const staff = "staff@example.com";
const staffIp = "198.51.100.7";
const auditScope = "https://www.googleapis.com/auth/admin.reports.audit.readonly";
const mailScope = "https://mail.google.com/";
const client = { client_id: "mail-app", client_secret: "mail-secret", redirect: "https://mail.example.net/callback" };

type Nested = { name: string; value?: string; intValue?: string; boolValue?: boolean; multiValue?: string[] };
type Parameter = Nested & {
  messageValue?: { parameter: Array<Parameter> };
  multiMessageValue?: Array<{ parameter: Array<Parameter> }>;
};
type Activity = {
  actor: { callerType?: string; email: string; profileId: string };
  ipAddress?: string;
  events: Array<{ type: string; name: string; parameters: Parameter[] }>;
};

const message = (activity: Activity, name: string) =>
  activity.events[0].parameters.find((p) => p.name === name)?.messageValue?.parameter ?? [];
const field = (parameters: Parameter[], name: string) => parameters.find((p) => p.name === name);
const mailEventType = (activity: Activity) => field(message(activity, "event_info"), "mail_event_type")?.intValue;

const raw = Buffer.from(
  [
    "From: Sam Staff <staff@example.com>",
    "To: Ada Admin <admin@example.com>, partner@example.net",
    "Subject: Quarterly figures",
    "Message-ID: <figures-1@example.com>",
    "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="b1"',
    "",
    "--b1",
    "Content-Type: text/plain",
    "",
    "See attached.",
    "--b1",
    'Content-Type: text/csv; name="figures.csv"',
    'Content-Disposition: attachment; filename="figures.csv"',
    "",
    "a,b",
    "--b1--",
    "",
  ].join("\r\n"),
).toString("base64url");

async function fixture() {
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
    oauth_clients: [{ ...client, name: "Mail app", redirect_uris: [client.redirect] }],
  });

  const send = (path: string, init: RequestInit = {}, token?: string) => {
    const request = new Request(`${base}${path}`, {
      ...init,
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        "Content-Type": init.body instanceof URLSearchParams ? "application/x-www-form-urlencoded" : "application/json",
      },
    });
    setClientAddress(request, staffIp);
    return app.fetch(request);
  };
  async function grant(email: string, scope: string) {
    const authorize = await send("/o/oauth2/v2/auth/callback", {
      method: "POST",
      body: new URLSearchParams({ email, redirect_uri: client.redirect, scope, client_id: client.client_id }),
    });
    const code = new URL(authorize.headers.get("Location")!).searchParams.get("code")!;
    const exchange = await send("/oauth2/token", {
      method: "POST",
      body: new URLSearchParams({
        client_id: client.client_id,
        client_secret: client.client_secret,
        grant_type: "authorization_code",
        code,
        redirect_uri: client.redirect,
      }),
    });
    return ((await exchange.json()) as { access_token: string }).access_token;
  }
  const staffToken = await grant(staff, mailScope);
  const adminToken = await grant(admin, auditScope);
  const mail = (path: string, method = "GET", body?: unknown) =>
    send(`/gmail/v1/users/me${path}`, { method, ...(body ? { body: JSON.stringify(body) } : {}) }, staffToken);

  /** The Gmail activities, oldest first. */
  async function report(query = ""): Promise<Activity[]> {
    const now = Date.now();
    const window = `startTime=${new Date(now - 60_000).toISOString()}&endTime=${new Date(now + 60_000).toISOString()}`;
    const response = await send(`${gmailReport}?${window}${query}`, {}, adminToken);
    expect(response.status).toBe(200);
    return (((await response.json()) as { items?: Activity[] }).items ?? []).reverse();
  }
  return { mail, report };
}

describe("Google Reports API Gmail log events", () => {
  it("records a sent message as a delivery event with Gmail's event and message info", async () => {
    const { mail, report } = await fixture();
    const sent = await mail("/messages/send", "POST", { raw });
    expect(sent.status).toBe(200);
    const sentSize = ((await sent.json()) as { sizeEstimate: number }).sizeEstimate;

    const [activity] = await report();
    expect(activity.actor).toMatchObject({ callerType: "USER", email: staff });
    expect(activity.ipAddress).toBe(staffIp);
    expect(activity.events[0]).toMatchObject({ type: "delivery_type", name: "delivery" });
    expect(activity.events[0].parameters.map((p) => p.name)).toEqual(["event_info", "message_info"]);

    const eventInfo = message(activity, "event_info");
    expect(field(eventInfo, "mail_event_type")).toEqual({ name: "mail_event_type", intValue: "1" });
    expect(field(eventInfo, "success")).toEqual({ name: "success", boolValue: true });
    expect(field(eventInfo, "timestamp_usec")?.intValue).toMatch(/^\d{16}$/);
    expect(field(eventInfo, "client_context")?.messageValue?.parameter).toEqual([
      { name: "client_type", value: "API" },
    ]);

    const info = message(activity, "message_info");
    expect(field(info, "rfc2822_message_id")?.value).toBe("<figures-1@example.com>");
    expect(field(info, "subject")?.value).toBe("Quarterly figures");
    expect(field(info, "source")?.messageValue?.parameter).toEqual([
      { name: "address", value: staff },
      { name: "from_header_address", value: staff },
    ]);
    expect(field(info, "destination")?.multiMessageValue).toEqual([
      { parameter: [{ name: "address", value: admin }] },
      { parameter: [{ name: "address", value: "partner@example.net" }] },
    ]);
    expect(field(info, "payload_size")?.intValue).toBe(String(sentSize));
    expect(field(info, "num_message_attachments")?.intValue).toBe("1");
  });

  it("records what a user or app does with a message, each as its documented mail event type", async () => {
    const { mail, report } = await fixture();
    const sent = (await (await mail("/messages/send", "POST", { raw })).json()) as { id: string };
    const full = (await (await mail(`/messages/${sent.id}`)).json()) as {
      payload: { parts: Array<{ body: { attachmentId?: string } }> };
    };
    const attachmentId = full.payload.parts.find((part) => part.body.attachmentId)!.body.attachmentId!;
    expect((await mail(`/messages/${sent.id}/attachments/${attachmentId}`)).status).toBe(200);
    expect((await mail(`/messages/${sent.id}/modify`, "POST", { addLabelIds: ["INBOX"] })).status).toBe(200);
    expect((await mail(`/messages/${sent.id}/modify`, "POST", { addLabelIds: ["UNREAD"] })).status).toBe(200);
    expect((await mail(`/messages/${sent.id}/modify`, "POST", { removeLabelIds: ["INBOX"] })).status).toBe(200);
    expect((await mail(`/messages/${sent.id}/trash`, "POST")).status).toBe(200);
    expect((await mail(`/messages/${sent.id}/untrash`, "POST")).status).toBe(200);
    expect((await mail(`/messages/${sent.id}`, "DELETE")).status).toBe(204);

    const activities = await report();
    // 1 sent, 33 accessed by an application, 17 attachment downloaded, 12 moved to Inbox, 8 marked unread,
    // 26 archived, 13 moved to Trash, 14 removed from Trash, 27 permanently deleted.
    expect(activities.map(mailEventType)).toEqual(["1", "33", "17", "12", "8", "26", "13", "14", "27"]);
    for (const activity of activities) {
      expect(activity.actor.email).toBe(staff);
      expect(field(message(activity, "message_info"), "rfc2822_message_id")?.value).toBe("<figures-1@example.com>");
    }
  });

  it("filters on the mail event type by its full parameter name", async () => {
    const { mail, report } = await fixture();
    const sent = (await (await mail("/messages/send", "POST", { raw })).json()) as { id: string };
    await mail(`/messages/${sent.id}/trash`, "POST");
    const trashed = await report("&eventName=delivery&filters=event_info.mail_event_type==13");
    expect(trashed.map(mailEventType)).toEqual(["13"]);
  });

  it("records nothing for a refused or unknown message", async () => {
    const { mail, report } = await fixture();
    expect((await mail("/messages/nope/trash", "POST")).status).toBe(404);
    expect((await mail("/messages/nope")).status).toBe(404);
    expect(await report()).toEqual([]);
  });
});
