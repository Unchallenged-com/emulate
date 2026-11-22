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
const calendarReport = "/admin/reports/v1/activity/users/all/applications/calendar";
const admin = "admin@example.com";
const staff = "staff@example.com";
const staffIp = "198.51.100.9";
const auditScope = "https://www.googleapis.com/auth/admin.reports.audit.readonly";
const calendarScope = "https://www.googleapis.com/auth/calendar";
const client = { client_id: "cal-app", client_secret: "cal-secret", redirect: "https://cal.example.net/callback" };

type Parameter = { name: string; value?: string; intValue?: string; boolValue?: boolean };
type Activity = {
  actor: Record<string, unknown>;
  ownerDomain?: string;
  ipAddress?: string;
  events: Array<{ type: string; name: string; parameters: Parameter[] }>;
};

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
    oauth_clients: [{ ...client, name: "Calendar app", redirect_uris: [client.redirect] }],
  });

  const send = (path: string, init: RequestInit = {}, token?: string, contentType = "application/json") => {
    const request = new Request(`${base}${path}`, {
      ...init,
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        "Content-Type": contentType,
        "User-Agent": "calendar-sync/1.0",
      },
    });
    setClientAddress(request, staffIp);
    return app.fetch(request);
  };
  async function grant(email: string, scope: string) {
    const form = "application/x-www-form-urlencoded";
    const authorize = await send(
      "/o/oauth2/v2/auth/callback",
      {
        method: "POST",
        body: new URLSearchParams({ email, redirect_uri: client.redirect, scope, client_id: client.client_id }),
      },
      undefined,
      form,
    );
    const code = new URL(authorize.headers.get("Location")!).searchParams.get("code")!;
    const exchange = await send(
      "/oauth2/token",
      {
        method: "POST",
        body: new URLSearchParams({
          client_id: client.client_id,
          client_secret: client.client_secret,
          grant_type: "authorization_code",
          code,
          redirect_uri: client.redirect,
        }),
      },
      undefined,
      form,
    );
    return ((await exchange.json()) as { access_token: string }).access_token;
  }
  const staffToken = await grant(staff, calendarScope);
  const adminToken = await grant(admin, auditScope);
  const calendar = (path: string, method = "GET", body?: unknown) =>
    send(`/calendar/v3${path}`, { method, ...(body ? { body: JSON.stringify(body) } : {}) }, staffToken);

  /** The Calendar activities, oldest first. */
  async function report(): Promise<Activity[]> {
    const response = await send(calendarReport, {}, adminToken);
    expect(response.status).toBe(200);
    return (((await response.json()) as { items?: Activity[] }).items ?? []).reverse();
  }
  return { calendar, report };
}

// "The start time of the event in seconds, stored in Gregorian time": the Unix time plus 62135683200 seconds.
const gregorian = (iso: string) => String(Date.parse(iso) / 1000 + 62135683200);

describe("Google Reports API Calendar events", () => {
  it("records an event created through the API, with its guests, and its deletion", async () => {
    const { calendar, report } = await fixture();
    const created = await calendar("/calendars/primary/events", "POST", {
      summary: "Budget review",
      start: { dateTime: "2026-12-01T09:00:00Z" },
      end: { dateTime: "2026-12-01T10:00:00Z" },
      attendees: [{ email: admin }],
    });
    expect(created.status).toBe(200);
    const { id } = (await created.json()) as { id: string };
    expect((await calendar(`/calendars/primary/events/${id}`, "DELETE")).status).toBe(204);
    expect((await calendar("/calendars/primary/events")).status).toBe(200);

    const [creation, deletion, ...rest] = await report();
    expect(rest).toEqual([]);
    expect(creation.actor).toEqual({ email: staff, profileId: expect.any(String) });
    expect(creation.ownerDomain).toBe("example.com");
    expect(creation.ipAddress).toBe(staffIp);
    const common = [
      { name: "event_id", value: id },
      { name: "organizer_calendar_id", value: staff },
      { name: "calendar_id", value: staff },
      { name: "event_title", value: "Budget review" },
      { name: "recurring", value: "no" },
      { name: "client_side_encrypted", value: "no" },
    ];
    const times = [
      { name: "start_time", intValue: gregorian("2026-12-01T09:00:00Z") },
      { name: "end_time", intValue: gregorian("2026-12-01T10:00:00Z") },
    ];
    const origin = [
      { name: "api_kind", value: "api_v3" },
      { name: "user_agent", value: "calendar-sync/1.0" },
    ];
    expect(creation.events).toEqual([
      { type: "event_change", name: "create_event", parameters: [...common, ...times, ...origin] },
      {
        type: "event_change",
        name: "add_event_guest",
        parameters: [...common, { name: "event_guest", value: admin }, ...origin],
      },
    ]);
    expect(deletion.events).toEqual([
      { type: "event_change", name: "delete_event", parameters: [...common, ...times, ...origin] },
    ]);
  });

  it("records nothing for a refused event or an unknown one", async () => {
    const { calendar, report } = await fixture();
    expect((await calendar("/calendars/primary/events", "POST", { summary: "No times" })).status).toBe(400);
    expect((await calendar("/calendars/primary/events/nope", "DELETE")).status).toBe(404);
    expect(await report()).toEqual([]);
  });
});
