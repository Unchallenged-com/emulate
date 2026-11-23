import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { Hono, Store, WebhookDispatcher, authMiddleware, type AppEnv, type TokenMap } from "@emulators/core";
import { googlePlugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";
const reports = "/admin/reports/v1/activity/users/all/applications";
const admin = "admin@example.com";
const scopes = ["admin.directory.user", "admin.reports.audit.readonly"]
  .map((name) => `https://www.googleapis.com/auth/${name}`)
  .join(" ");
const console_ = { client_id: "it-console", client_secret: "it-secret", redirect: "http://127.0.0.1:8080/" };
const collector = { client_id: "siem", client_secret: "siem-secret", redirect: "https://siem.example.com/callback" };
const SIX_HOURS = 21600 * 1000;

type Received = { method: string; headers: IncomingMessage["headers"]; body: string };

// A local endpoint standing in for the collector a channel delivers to.
const servers: Server[] = [];
async function receiver() {
  const received: Received[] = [];
  const server: Server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      received.push({ method: req.method ?? "", headers: req.headers, body });
      res.writeHead(200);
      res.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  servers.push(server);
  return { address: `http://127.0.0.1:${(server.address() as AddressInfo).port}/notifications`, received };
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise((resolve) => server.close(resolve))));
});

async function until(condition: () => boolean, timeout = 2000) {
  const deadline = Date.now() + timeout;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error("timed out");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}
const settle = () => new Promise((resolve) => setTimeout(resolve, 150));

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
        client_id: collector.client_id,
        client_secret: collector.client_secret,
        name: "SIEM",
        redirect_uris: [collector.redirect],
      },
    ],
  });

  const form = (path: string, fields: Record<string, string>) =>
    app.request(path, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(fields),
    });
  async function grant(client: typeof console_, scope = scopes) {
    const authorize = await form("/o/oauth2/v2/auth/callback", {
      email: admin,
      redirect_uri: client.redirect,
      scope,
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
  const createUser = (token: string, email: string) =>
    request("/admin/directory/v1/users", token, "POST", {
      primaryEmail: email,
      name: { givenName: "New", familyName: "User" },
      password: "Secret-pass-123",
    });
  return { app, grant, request, createUser };
}

type Channel = {
  kind: string;
  id: string;
  resourceId: string;
  resourceUri: string;
  token?: string;
  expiration: string;
};

describe("Google Reports API push notifications", () => {
  it("creates a channel and sends its sync message", async () => {
    const { grant, request } = await fixture();
    const token = await grant(collector);
    const { address, received } = await receiver();

    const before = Date.now();
    const response = await request(`${reports}/admin/watch`, token, "POST", {
      id: "channel-1",
      type: "web_hook",
      address,
      token: "target=siem",
      expiration: String(before + 3600 * 1000),
    });
    expect(response.status).toBe(200);
    const channel = (await response.json()) as Channel;
    expect(channel).toMatchObject({
      kind: "api#channel",
      id: "channel-1",
      resourceUri: `${base}/admin/reports/v1/activity/users/all/applications/admin?alt=json`,
      token: "target=siem",
      expiration: String(before + 3600 * 1000),
    });
    expect(channel.resourceId).toMatch(/^\S+$/);

    await until(() => received.length === 1);
    const [sync] = received;
    expect(sync.method).toBe("POST");
    expect(sync.headers).toMatchObject({
      "x-goog-channel-id": "channel-1",
      "x-goog-channel-token": "target=siem",
      "x-goog-channel-expiration": new Date(before + 3600 * 1000).toUTCString(),
      "x-goog-resource-id": channel.resourceId,
      "x-goog-resource-uri": channel.resourceUri,
      "x-goog-resource-state": "sync",
      "x-goog-message-number": "1",
    });
    expect(sync.headers["user-agent"]).toMatch(/^APIs-Google/);
    expect(sync.body).toBe("");
  });

  it("caps the channel's lifetime at six hours, its default", async () => {
    const { grant, request } = await fixture();
    const token = await grant(collector);
    const { address } = await receiver();

    const before = Date.now();
    const unset = (await (
      await request(`${reports}/login/watch`, token, "POST", { id: "a", type: "web_hook", address })
    ).json()) as Channel;
    const tooLong = (await (
      await request(`${reports}/login/watch`, token, "POST", {
        id: "b",
        type: "web_hook",
        address,
        expiration: String(before + 2 * SIX_HOURS),
      })
    ).json()) as Channel;
    const after = Date.now();
    for (const channel of [unset, tooLong]) {
      expect(Number(channel.expiration)).toBeGreaterThanOrEqual(before + SIX_HOURS);
      expect(Number(channel.expiration)).toBeLessThanOrEqual(after + SIX_HOURS);
    }
    expect(unset.token).toBeUndefined();
  });

  it("delivers each new matching activity as the list returns it", async () => {
    const { grant, request, createUser } = await fixture();
    const fromConsole = await grant(console_);
    const token = await grant(collector);
    const { address, received } = await receiver();

    const watch = await request(`${reports}/admin/watch?eventName=CREATE_USER`, token, "POST", {
      id: "creations",
      type: "web_hook",
      address,
      token: "t",
    });
    const channel = (await watch.json()) as Channel;
    await until(() => received.length === 1);

    expect((await createUser(fromConsole, "first@example.com")).status).toBe(200);
    expect((await request("/admin/directory/v1/users/first@example.com", fromConsole, "DELETE")).status).toBe(200);
    expect((await createUser(fromConsole, "second@example.com")).status).toBe(200);
    await until(() => received.length === 3);
    await settle();
    expect(received).toHaveLength(3);

    const list = await request(`${reports}/admin?eventName=CREATE_USER`, token);
    const { items } = (await list.json()) as { items: unknown[] };
    const notifications = received.slice(1);
    expect(notifications.map((n) => JSON.parse(n.body))).toEqual([items[1], items[0]]);
    for (const notification of notifications) {
      expect(notification.headers).toMatchObject({
        "content-type": "application/json; utf-8",
        "x-goog-channel-id": "creations",
        "x-goog-channel-token": "t",
        "x-goog-resource-id": channel.resourceId,
        "x-goog-resource-uri": channel.resourceUri,
        "x-goog-resource-state": "CREATE_USER",
      });
    }
    const numbers = notifications.map((n) => Number(n.headers["x-goog-message-number"]));
    expect(numbers[0]).toBeGreaterThan(1);
    expect(numbers[1]).toBeGreaterThan(numbers[0]);
  });

  it("delivers only the activities of the watched user and application", async () => {
    const { grant, request, createUser } = await fixture();
    const fromConsole = await grant(console_);
    const token = await grant(collector);
    const { address, received } = await receiver();
    expect((await createUser(fromConsole, "someone@example.com")).status).toBe(200);

    const watch = (userKey: string, application: string, id: string) =>
      request(`/admin/reports/v1/activity/users/${userKey}/applications/${application}/watch`, token, "POST", {
        id,
        type: "web_hook",
        address,
      });
    expect((await watch("someone@example.com", "admin", "x")).status).toBe(200);
    expect((await watch("unknown@example.com", "admin", "y")).status).toBe(400);
    expect((await watch("all", "token", "z")).status).toBe(200);
    await until(() => received.length === 2);

    // The administrator, not the user it creates, is the actor, and no new grant reaches the token application.
    expect((await createUser(fromConsole, "other@example.com")).status).toBe(200);
    await settle();
    expect(received.map((r) => r.headers["x-goog-resource-state"])).toEqual(["sync", "sync"]);
  });

  it("stops a channel for the user and client that created it", async () => {
    const { grant, request, createUser } = await fixture();
    const fromConsole = await grant(console_);
    const token = await grant(collector);
    const { address, received } = await receiver();

    const channel = (await (
      await request(`${reports}/admin/watch`, token, "POST", { id: "stop-me", type: "web_hook", address })
    ).json()) as Channel;
    await until(() => received.length === 1);

    const otherClient = await request("/admin/reports_v1/channels/stop", fromConsole, "POST", {
      id: channel.id,
      resourceId: channel.resourceId,
    });
    expect(otherClient.status).toBe(404);
    const stopped = await request("/admin/reports_v1/channels/stop", token, "POST", {
      id: channel.id,
      resourceId: channel.resourceId,
    });
    expect(stopped.status).toBe(200);
    expect(await stopped.text()).toBe("");

    expect((await createUser(fromConsole, "after@example.com")).status).toBe(200);
    await settle();
    expect(received).toHaveLength(1);
    const again = await request("/admin/reports_v1/channels/stop", token, "POST", {
      id: channel.id,
      resourceId: channel.resourceId,
    });
    expect(again.status).toBe(404);
  });

  it("sends nothing once the channel has expired", async () => {
    const { grant, request, createUser } = await fixture();
    const fromConsole = await grant(console_);
    const token = await grant(collector);
    const { address, received } = await receiver();

    await request(`${reports}/admin/watch`, token, "POST", {
      id: "short",
      type: "web_hook",
      address,
      expiration: String(Date.now() + 200),
    });
    await until(() => received.length === 1);
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect((await createUser(fromConsole, "late@example.com")).status).toBe(200);
    await settle();
    expect(received).toHaveLength(1);
  });

  it("refuses an address that is not HTTPS, except HTTP on the loopback interface", async () => {
    const { grant, request } = await fixture();
    const token = await grant(collector);
    const watch = (id: string, address: string) =>
      request(`${reports}/admin/watch`, token, "POST", { id, type: "web_hook", address });

    for (const address of ["http://siem.example.com/notifications", "projects/p/topics/t", "ftp://127.0.0.1/x"]) {
      const refused = await watch("refused", address);
      expect(refused.status).toBe(400);
      const message = "Invalid webhook URL. Must be a valid URL starting with https";
      expect(await refused.json()).toEqual({
        error: { errors: [{ domain: "push", reason: "push.webhookUrlInvalid", message }], code: 400, message },
      });
    }
    // Port 1 refuses the connection, so the sync message is dropped without leaving the host.
    for (const address of [
      "https://127.0.0.1:1/notifications",
      "http://localhost:1/notifications",
      "http://127.0.0.1:1/notifications",
      "http://[::1]:1/notifications",
    ]) {
      expect((await watch(address, address)).status).toBe(200);
    }
  });

  it("answers the emulator's choices where Google does not document one", async () => {
    const { grant, request } = await fixture();
    const token = await grant(collector);
    const { address, received } = await receiver();
    const watch = (body: Record<string, unknown>) => request(`${reports}/admin/watch`, token, "POST", body);

    for (const body of [
      { type: "web_hook", address },
      { id: "c", type: "email", address },
      { id: "c", type: "web_hook" },
    ]) {
      expect((await watch(body)).status).toBe(400);
    }
    // A duplicate id and an expiration already past are accepted; the expired channel sends nothing after its sync.
    expect((await watch({ id: "same", type: "web_hook", address })).status).toBe(200);
    expect((await watch({ id: "same", type: "web_hook", address })).status).toBe(200);
    const past = await watch({ id: "past", type: "web_hook", address, expiration: String(Date.now() - 1000) });
    expect(past.status).toBe(200);
    await until(() => received.length === 3);

    const unknown = await request("/admin/reports_v1/channels/stop", token, "POST", { id: "none", resourceId: "r" });
    expect(unknown.status).toBe(404);
    expect(((await unknown.json()) as { error: { message: string } }).error.message).toBe("Channel not found");
  });

  it("needs the audit scope and refuses the filters the list refuses", async () => {
    const { grant, request } = await fixture();
    const directoryOnly = await grant(collector, "https://www.googleapis.com/auth/admin.directory.user");
    const token = await grant(collector);
    const { address } = await receiver();
    const body = { id: "c", type: "web_hook", address };

    expect((await request(`${reports}/admin/watch`, directoryOnly, "POST", body)).status).toBe(403);
    expect(
      (await request("/admin/reports_v1/channels/stop", directoryOnly, "POST", { id: "c", resourceId: "r" })).status,
    ).toBe(403);
    expect((await request(`${reports}/admin/watch?orgUnitID=id:abc`, token, "POST", body)).status).toBe(400);
    expect((await request(`${reports}/not_an_app/watch`, token, "POST", body)).status).toBe(400);
  });

  it("describes watch and channels.stop in the discovery document", async () => {
    const { app } = await fixture();
    const discovery = (await (await app.request("/discovery/v1/apis/admin/reports_v1/rest")).json()) as {
      resources: Record<string, { methods: Record<string, { id: string; path: string; httpMethod: string }> }>;
      schemas: Record<string, unknown>;
    };
    expect(discovery.resources.activities.methods.watch).toMatchObject({
      id: "reports.activities.watch",
      httpMethod: "POST",
      path: "admin/reports/v1/activity/users/{userKey}/applications/{applicationName}/watch",
    });
    expect(discovery.resources.channels.methods.stop).toMatchObject({
      id: "admin.channels.stop",
      httpMethod: "POST",
      path: "admin/reports_v1/channels/stop",
    });
    expect(discovery.schemas.Channel).toBeDefined();
  });
});
