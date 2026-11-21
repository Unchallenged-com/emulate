import { describe, expect, it } from "vitest";
import { Hono, Store, WebhookDispatcher, authMiddleware } from "@emulators/core";
import type { TokenMap } from "@emulators/core";
import { getOktaStore, oktaPlugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";
const admin = { Authorization: "SSWS admin-token", "Content-Type": "application/json" };

function createTestApp() {
  const tokenMap: TokenMap = new Map([["admin-token", { login: "admin@example.com", id: 1, scopes: ["okta.*"] }]]);
  const app = new Hono();
  app.use("*", authMiddleware(tokenMap));
  const store = new Store();
  oktaPlugin.register(app as any, store, new WebhookDispatcher(), base, tokenMap);
  oktaPlugin.seed?.(store, base);
  seedFromConfig(store, base, {
    users: [{ okta_id: "00u_admin", login: "admin@example.com", first_name: "Ada", last_name: "Admin" }],
  });
  return { app, store };
}

async function createUser(app: Hono<any>, login: string): Promise<string> {
  const response = await app.request(`${base}/api/v1/users?activate=false`, {
    method: "POST",
    headers: admin,
    body: JSON.stringify({ profile: { login, email: login, firstName: "New", lastName: "User" } }),
  });
  return ((await response.json()) as { id: string }).id;
}

async function logs(app: Hono<any>, query = "") {
  const response = await app.request(`${base}/api/v1/logs${query}`, { headers: admin });
  return { response, events: (await response.json()) as any[] };
}

function links(response: Response): Record<string, string> {
  const result: Record<string, string> = {};
  for (const part of (response.headers.get("Link") ?? "").split(/,\s*(?=<)/)) {
    const match = /^<([^>]+)>;\s*rel="(\w+)"$/.exec(part.trim());
    if (match) result[match[2]!] = match[1]!;
  }
  return result;
}

function pathOf(url: string): string {
  const parsed = new URL(url);
  return `${parsed.pathname}${parsed.search}`;
}

describe("Okta System Log API", () => {
  it("requires management authentication", async () => {
    const { app } = createTestApp();
    const response = await app.request(`${base}/api/v1/logs`);
    expect(response.status).toBe(401);
    expect(((await response.json()) as { errorCode: string }).errorCode).toBe("E0000004");
  });

  it("returns an empty list, a self link and a next link when nothing was recorded", async () => {
    const { app } = createTestApp();
    const { response, events } = await logs(app);
    expect(response.status).toBe(200);
    expect(events).toEqual([]);
    const rel = links(response);
    expect(rel.self).toBe(`${base}/api/v1/logs`);
    expect(rel.next).toBeDefined();
  });

  it("polls with the next link and returns each event once", async () => {
    const { app } = createTestApp();
    await createUser(app, "one@example.com");

    const first = await logs(app);
    expect(first.events.map((event) => event.eventType)).toEqual(["user.lifecycle.create"]);
    const next = links(first.response).next!;
    expect(new URL(next).searchParams.get("after")).toMatch(/^\d+_\d+$/);

    const empty = await logs(app, pathOf(next).replace("/api/v1/logs", ""));
    expect(empty.events).toEqual([]);
    const stillNext = links(empty.response).next!;
    expect(stillNext).toBeDefined();

    await createUser(app, "two@example.com");
    const second = await logs(app, pathOf(stillNext).replace("/api/v1/logs", ""));
    expect(second.events).toHaveLength(1);
    expect(second.events[0].target[0].alternateId).toBe("two@example.com");
  });

  it("pages with limit and ends a bounded request without a next link", async () => {
    const { app } = createTestApp();
    for (const login of ["a@example.com", "b@example.com", "c@example.com"]) await createUser(app, login);
    const since = new Date(Date.now() - 60_000).toISOString();
    const until = new Date(Date.now() + 60_000).toISOString();
    const query = `?since=${encodeURIComponent(since)}&until=${encodeURIComponent(until)}&limit=2`;

    const first = await logs(app, query);
    expect(first.events.map((event) => event.target[0].alternateId)).toEqual(["a@example.com", "b@example.com"]);
    const next = links(first.response).next!;
    expect(new URL(next).searchParams.get("since")).toBe(since);

    const second = await logs(app, pathOf(next).replace("/api/v1/logs", ""));
    expect(second.events.map((event) => event.target[0].alternateId)).toEqual(["c@example.com"]);
    expect(links(second.response).next).toBeUndefined();
  });

  it("sorts newest first with sortOrder=DESCENDING", async () => {
    const { app } = createTestApp();
    for (const login of ["a@example.com", "b@example.com"]) await createUser(app, login);
    const { events, response } = await logs(app, "?sortOrder=DESCENDING");
    expect(events.map((event) => event.target[0].alternateId)).toEqual(["b@example.com", "a@example.com"]);
    expect(links(response).next).toBeUndefined();
  });

  it("filters with SCIM expressions on event fields and targets", async () => {
    const { app } = createTestApp();
    const id = await createUser(app, "a@example.com");
    await app.request(`${base}/api/v1/users/${id}/lifecycle/activate`, { method: "POST", headers: admin });
    await createUser(app, "b@example.com");

    const byType = await logs(app, `?filter=${encodeURIComponent('eventType eq "user.lifecycle.activate"')}`);
    expect(byType.events.map((event) => event.eventType)).toEqual(["user.lifecycle.activate"]);

    const byTarget = await logs(
      app,
      `?filter=${encodeURIComponent(`target.id eq "${id}" and (eventType sw "user.lifecycle" or outcome.result eq "FAILURE")`)}`,
    );
    expect(byTarget.events.map((event) => event.eventType)).toEqual([
      "user.lifecycle.create",
      "user.lifecycle.activate",
    ]);

    const notCreate = await logs(app, `?filter=${encodeURIComponent('not (eventType ew ".create")')}`);
    expect(notCreate.events.map((event) => event.eventType)).toEqual(["user.lifecycle.activate"]);

    const byActor = await logs(app, `?filter=${encodeURIComponent('actor.id eq "00u_admin"')}`);
    expect(byActor.events).toHaveLength(3);
  });

  it("matches keywords case-insensitively with q", async () => {
    const { app } = createTestApp();
    await createUser(app, "alice@example.com");
    await createUser(app, "bob@example.com");
    const { events } = await logs(app, "?q=ALICE@EXAMPLE.COM");
    expect(events.map((event) => event.target[0].alternateId)).toEqual(["alice@example.com"]);
  });

  it("answers Okta's errors for invalid filters, dates and keywords", async () => {
    const { app } = createTestApp();

    const operator = await logs(app, `?filter=${encodeURIComponent('displayMessage eqq "Create okta user"')}`);
    expect(operator.response.status).toBe(400);
    expect(operator.events).toMatchObject({
      errorCode: "E0000053",
      errorSummary:
        "Invalid filter 'displayMessage eqq \"Create okta user\"': Unrecognized attribute operator 'eqq' at position 15. Expected: eq,co,sw,pr,gt,ge,lt,le",
    });

    const field = await logs(app, `?filter=${encodeURIComponent('some_invalid_field eq "x"')}`);
    expect(field.events).toMatchObject({
      errorCode: "E0000053",
      errorSummary: "field is not valid: some_invalid_field",
    });

    const contains = await logs(app, `?filter=${encodeURIComponent('debugContext.debugData.url co "/oauth/"')}`);
    expect(contains.events).toMatchObject({
      errorCode: "E0000031",
      errorSummary:
        "The supplied combination of operator and field is not currently supported. Operator: co, Field: debugContext.debugData.url",
    });

    const until = await logs(app, "?until=yesterday");
    expect(until.response.status).toBe(400);
    expect(until.events).toMatchObject({
      errorCode: "E0000001",
      errorSummary:
        "Api validation failed: 'until': The date format in your query is not recognized. Please enter dates using ISO8601 string format. 'until': must be a valid date-time or empty.",
      errorCauses: [
        {
          errorSummary:
            "until: The date format in your query is not recognized. Please enter dates using ISO8601 string format.",
        },
        { errorSummary: "until: must be a valid date-time or empty." },
      ],
    });

    const old = await logs(app, `?since=${new Date(Date.now() - 200 * 24 * 3600 * 1000).toISOString()}`);
    expect(old.events).toMatchObject({
      errorCode: "E0000053",
      errorSummary: "Invalid parameter: The since parameter is over 180 days prior to the current day.",
    });

    const keyword = await logs(app, `?q=${"x".repeat(41)}`);
    expect(keyword.events).toMatchObject({ errorCode: "E0000001" });
  });

  it("does not return events older than 90 days", async () => {
    const { app, store } = createTestApp();
    await createUser(app, "old@example.com");
    const entry = getOktaStore(store).logEvents.all()[0]!;
    const published = new Date(Date.now() - 91 * 24 * 3600 * 1000).toISOString();
    getOktaStore(store).logEvents.update(entry.id, { published, event: { ...entry.event, published } });
    const since = new Date(Date.now() - 100 * 24 * 3600 * 1000).toISOString();
    const { events } = await logs(app, `?since=${since}`);
    expect(events).toEqual([]);
  });
});
