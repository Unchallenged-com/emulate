import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { Hono, Store, WebhookDispatcher, authMiddleware } from "@emulators/core";
import type { TokenMap } from "@emulators/core";
import { oktaPlugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";
const admin = { Authorization: "SSWS admin-token", "Content-Type": "application/json" };

type Received = { method: string; headers: IncomingMessage["headers"]; body: string };

// A local endpoint standing in for the service an event hook calls.
async function receiver(respond: (request: Received) => { status: number; body?: string }) {
  const received: Received[] = [];
  const server: Server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      const request = { method: req.method ?? "", headers: req.headers, body };
      received.push(request);
      const answer = respond(request);
      res.writeHead(answer.status, { "Content-Type": "application/json" });
      res.end(answer.body ?? "");
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  servers.push(server);
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/okta`, received };
}

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise((resolve) => server.close(resolve))));
});

// Answers Okta's one-time verification, and accepts deliveries.
function verifyingEndpoint(request: Received) {
  const challenge = request.headers["x-okta-verification-challenge"];
  if (request.method === "GET") return { status: 200, body: JSON.stringify({ verification: challenge }) };
  return { status: 200 };
}

function createTestApp() {
  const tokenMap: TokenMap = new Map([["admin-token", { login: "ada@example.com", id: 1, scopes: ["okta.*"] }]]);
  const app = new Hono();
  app.use("*", authMiddleware(tokenMap));
  const store = new Store();
  oktaPlugin.register(app as any, store, new WebhookDispatcher(), base, tokenMap);
  oktaPlugin.seed?.(store, base);
  seedFromConfig(store, base, {
    users: [
      { okta_id: "00u_ada", login: "ada@example.com", first_name: "Ada", last_name: "Admin" },
      { okta_id: "00u_bob", login: "bob@example.com", first_name: "Bob", last_name: "Roe" },
    ],
  });
  return app;
}

async function call(app: Hono<any>, method: string, path: string, body?: unknown) {
  const response = await app.request(`${base}${path}`, {
    method,
    headers: admin,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

async function events(app: Hono<any>, prefix: string): Promise<any[]> {
  return (await call(app, "GET", `/api/v1/logs?filter=${encodeURIComponent(`eventType sw "${prefix}"`)}`)).body;
}

function hookBody(uri: string, items = ["user.lifecycle.suspend"]) {
  return {
    name: "SIEM",
    events: { type: "EVENT_TYPE", items },
    channel: {
      type: "HTTP",
      version: "1.0.0",
      config: {
        uri,
        headers: [{ key: "X-Other-Header", value: "my-header-value" }],
        authScheme: { type: "HEADER", key: "Authorization", value: "my-shared-secret" },
      },
    },
  };
}

async function until(check: () => boolean, ms = 2000) {
  const start = Date.now();
  while (!check() && Date.now() - start < ms) await new Promise((resolve) => setTimeout(resolve, 10));
}

describe("Okta event hooks", () => {
  it("creates an active, unverified hook without returning its secret", async () => {
    const app = createTestApp();
    const created = await call(app, "POST", "/api/v1/eventHooks", hookBody("https://siem.example.com/okta"));
    expect(created.status).toBe(200);
    expect(created.body).toMatchObject({
      status: "ACTIVE",
      verificationStatus: "UNVERIFIED",
      name: "SIEM",
      createdBy: "00u_ada",
      events: { type: "EVENT_TYPE", items: ["user.lifecycle.suspend"], filter: null },
      channel: {
        type: "HTTP",
        version: "1.0.0",
        config: { method: "POST", authScheme: { type: "HEADER", key: "Authorization" } },
      },
    });
    expect(created.body.id).toMatch(/^who/);
    expect(JSON.stringify(created.body)).not.toContain("my-shared-secret");
    expect((await call(app, "POST", "/api/v1/eventHooks", hookBody("http://siem.example.com/okta"))).status).toBe(400);
    const [event] = await events(app, "event_hook");
    expect(event).toMatchObject({
      eventType: "event_hook.created",
      target: [{ id: created.body.id, type: "EventHook" }],
    });
  });

  it("verifies a hook with Okta's challenge, and delivers subscribed events in Okta's envelope", async () => {
    const endpoint = await receiver(verifyingEndpoint);
    const app = createTestApp();
    const hook = (await call(app, "POST", "/api/v1/eventHooks", hookBody(endpoint.url))).body;

    await call(app, "POST", "/api/v1/users/00u_bob/lifecycle/suspend");
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(endpoint.received).toEqual([]);

    const verified = await call(app, "POST", `/api/v1/eventHooks/${hook.id}/lifecycle/verify`);
    expect(verified.status).toBe(200);
    expect(verified.body.verificationStatus).toBe("VERIFIED");
    const [challenge] = endpoint.received;
    expect(challenge!.method).toBe("GET");
    expect(challenge!.headers["x-okta-verification-challenge"]).toBeTruthy();

    await call(app, "POST", "/api/v1/users/00u_bob/lifecycle/unsuspend");
    await call(app, "POST", "/api/v1/users/00u_bob/lifecycle/suspend");
    await until(() => endpoint.received.length > 1);

    const delivery = endpoint.received[1]!;
    expect(delivery.method).toBe("POST");
    expect(delivery.headers).toMatchObject({
      authorization: "my-shared-secret",
      "x-other-header": "my-header-value",
      "content-type": "application/json",
    });
    const payload = JSON.parse(delivery.body);
    expect(payload).toMatchObject({
      eventType: "com.okta.event_hook",
      eventTypeVersion: "1.0",
      cloudEventsVersion: "0.1",
      source: `${base}/api/v1/eventHooks/${hook.id}`,
      contentType: "application/json",
    });
    expect(payload.data.events.map((event: any) => event.eventType)).toEqual(["user.lifecycle.suspend"]);
    expect(payload.data.events[0].target[0].id).toBe("00u_bob");

    const [record] = await events(app, "event_hook.verified");
    expect(record).toMatchObject({
      outcome: { result: "SUCCESS" },
      legacyEventType: "platform.event_hook.verified.success",
    });
  });

  it("refuses a verification the endpoint does not answer, and records it", async () => {
    const endpoint = await receiver(() => ({ status: 200, body: JSON.stringify({ verification: "wrong" }) }));
    const app = createTestApp();
    const hook = (await call(app, "POST", "/api/v1/eventHooks", hookBody(endpoint.url))).body;
    const refused = await call(app, "POST", `/api/v1/eventHooks/${hook.id}/lifecycle/verify`);
    expect(refused.status).toBe(400);
    expect(refused.body).toMatchObject({
      errorCode: "E0000001",
      errorSummary: "Api validation failed: eventHook",
      errorCauses: [{ errorSummary: "Unable to verify event hook. Hook SIEM execution failed" }],
    });
    expect(endpoint.received).toHaveLength(2);
    const [record] = await events(app, "event_hook.verified");
    expect(record).toMatchObject({
      outcome: { result: "FAILURE" },
      legacyEventType: "platform.event_hook.verified.failure",
    });
  });

  it("retries a failed delivery once and records the failure", async () => {
    let verified = false;
    const endpoint = await receiver((request) => {
      if (request.method === "GET") {
        verified = true;
        return verifyingEndpoint(request);
      }
      return { status: 503 };
    });
    const app = createTestApp();
    const hook = (await call(app, "POST", "/api/v1/eventHooks", hookBody(endpoint.url))).body;
    await call(app, "POST", `/api/v1/eventHooks/${hook.id}/lifecycle/verify`);
    expect(verified).toBe(true);
    await call(app, "POST", "/api/v1/users/00u_bob/lifecycle/suspend");
    await until(() => endpoint.received.length >= 3);
    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(endpoint.received.filter((request) => request.method === "POST")).toHaveLength(2);
    const [failure] = await events(app, "event_hook.delivery");
    expect(failure).toMatchObject({
      displayMessage: "Event Hook Delivery Failed",
      actor: { type: "SystemPrincipal" },
      outcome: { result: "FAILURE", reason: "503 Service Unavailable. Exceeded maximum retry limit of 1" },
      transaction: { type: "JOB" },
      target: [{ id: hook.id, type: "EventHook" }],
    });
  });

  it("deletes only an inactive hook, and a changed channel needs a new verification", async () => {
    const endpoint = await receiver(verifyingEndpoint);
    const app = createTestApp();
    const hook = (await call(app, "POST", "/api/v1/eventHooks", hookBody(endpoint.url))).body;
    await call(app, "POST", `/api/v1/eventHooks/${hook.id}/lifecycle/verify`);
    const renamed = await call(app, "PUT", `/api/v1/eventHooks/${hook.id}`, { ...hookBody(endpoint.url), name: "SOC" });
    expect(renamed.body).toMatchObject({ name: "SOC", verificationStatus: "VERIFIED" });
    const moved = await call(app, "PUT", `/api/v1/eventHooks/${hook.id}`, hookBody(`${endpoint.url}/v2`));
    expect(moved.body.verificationStatus).toBe("UNVERIFIED");

    expect((await call(app, "DELETE", `/api/v1/eventHooks/${hook.id}`)).status).toBe(403);
    expect((await call(app, "POST", `/api/v1/eventHooks/${hook.id}/lifecycle/deactivate`)).body.status).toBe(
      "INACTIVE",
    );
    expect((await call(app, "DELETE", `/api/v1/eventHooks/${hook.id}`)).status).toBe(204);
    expect((await events(app, "event_hook")).map((event) => event.eventType)).toEqual([
      "event_hook.created",
      "event_hook.verified",
      "event_hook.updated",
      "event_hook.updated",
      "event_hook.deactivated",
      "event_hook.deleted",
    ]);
  });
});

describe("Okta log streams", () => {
  const aws = {
    type: "aws_eventbridge",
    name: "Example AWS EventBridge",
    settings: { eventSourceName: "okta-clinic", accountId: "123456789012", region: "eu-west-3" },
  };

  it("creates, replaces, deactivates and deletes a log stream, with their events", async () => {
    const app = createTestApp();
    const created = await call(app, "POST", "/api/v1/logStreams", aws);
    expect(created.status).toBe(200);
    expect(created.body).toMatchObject({ type: "aws_eventbridge", status: "ACTIVE", settings: aws.settings });
    const id = created.body.id;

    expect((await call(app, "PUT", `/api/v1/logStreams/${id}`, { ...aws, name: "Renamed" })).body.name).toBe("Renamed");
    const moved = await call(app, "PUT", `/api/v1/logStreams/${id}`, {
      ...aws,
      settings: { ...aws.settings, region: "us-east-1" },
    });
    expect(moved.status).toBe(400);

    const deactivated = await call(app, "POST", `/api/v1/logStreams/${id}/lifecycle/deactivate`);
    expect(deactivated).toEqual({ status: 200, body: null });
    expect((await call(app, "GET", `/api/v1/logStreams/${id}`)).body.status).toBe("INACTIVE");
    expect((await call(app, "DELETE", `/api/v1/logStreams/${id}`)).status).toBe(204);

    const recorded = await events(app, "system.log_stream");
    expect(recorded.map((event) => event.eventType)).toEqual([
      "system.log_stream.lifecycle.create",
      "system.log_stream.lifecycle.update",
      "system.log_stream.lifecycle.deactivate",
      "system.log_stream.lifecycle.delete",
    ]);
    expect(recorded[2]).toMatchObject({
      displayMessage: "Log stream deactivated",
      actor: { id: "00u_ada" },
      target: [{ id, type: "LogStream", displayName: "Renamed" }],
    });
  });

  it("validates settings and never returns the Splunk HEC token", async () => {
    const app = createTestApp();
    expect(
      (await call(app, "POST", "/api/v1/logStreams", { ...aws, settings: { ...aws.settings, accountId: "12" } }))
        .status,
    ).toBe(400);
    const splunk = await call(app, "POST", "/api/v1/logStreams", {
      type: "splunk_cloud_logstreaming",
      name: "Splunk Cloud",
      settings: { host: "clinic.splunkcloud.com", edition: "aws", token: "11111111-1111-2222-2222-222222222222" },
    });
    expect(splunk.status).toBe(200);
    expect(splunk.body.settings).toEqual({ host: "clinic.splunkcloud.com", edition: "aws" });
  });
});
