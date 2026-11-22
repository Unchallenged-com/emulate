import { describe, expect, it } from "vitest";
import { Hono, Store, WebhookDispatcher, authMiddleware } from "@emulators/core";
import type { TokenMap } from "@emulators/core";
import { oktaPlugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";
const admin = { Authorization: "SSWS admin-token", "Content-Type": "application/json" };

function createTestApp() {
  const tokenMap: TokenMap = new Map([["admin-token", { login: "ada@example.com", id: 1, scopes: ["okta.*"] }]]);
  const app = new Hono();
  app.use("*", authMiddleware(tokenMap));
  const store = new Store();
  oktaPlugin.register(app as any, store, new WebhookDispatcher(), base, tokenMap);
  oktaPlugin.seed?.(store, base);
  seedFromConfig(store, base, {
    users: [{ okta_id: "00u_ada", login: "ada@example.com", first_name: "Ada", last_name: "Admin" }],
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

const signOnPolicy = {
  type: "OKTA_SIGN_ON",
  name: "Clinic staff",
  description: "Sign-on for staff",
  conditions: { people: { groups: { include: ["00g_staff"] } } },
};

const mfaRule = {
  name: "Require MFA",
  conditions: { network: { connection: "ANYWHERE" } },
  actions: { signon: { access: "ALLOW", requireFactor: true, factorPromptMode: "ALWAYS" } },
};

describe("Okta policies", () => {
  it("creates, lists, replaces, deactivates and deletes a policy with its conditions as given", async () => {
    const app = createTestApp();
    const created = await call(app, "POST", "/api/v1/policies", signOnPolicy);
    expect(created.status).toBe(200);
    expect(created.body).toMatchObject({
      type: "OKTA_SIGN_ON",
      status: "ACTIVE",
      name: "Clinic staff",
      priority: 1,
      system: false,
      conditions: signOnPolicy.conditions,
    });
    expect(created.body.id).toMatch(/^00p/);
    const id = created.body.id;

    expect((await call(app, "GET", "/api/v1/policies?type=OKTA_SIGN_ON")).body.map((p: any) => p.id)).toEqual([id]);
    expect((await call(app, "GET", "/api/v1/policies?type=PASSWORD")).body).toEqual([]);
    expect((await call(app, "GET", "/api/v1/policies")).status).toBe(400);

    const replaced = await call(app, "PUT", `/api/v1/policies/${id}`, { ...signOnPolicy, name: "All staff" });
    expect(replaced.body.name).toBe("All staff");
    expect((await call(app, "POST", `/api/v1/policies/${id}/lifecycle/deactivate`)).status).toBe(204);
    expect((await call(app, "GET", `/api/v1/policies/${id}`)).body.status).toBe("INACTIVE");
    expect((await call(app, "DELETE", `/api/v1/policies/${id}`)).status).toBe(204);
    expect((await call(app, "GET", `/api/v1/policies/${id}`)).status).toBe(404);

    const [, update] = await events(app, "policy.lifecycle");
    expect(update.target[0].changeDetails).toEqual({
      from: { policyName: "Clinic staff" },
      to: { policyName: "All staff" },
    });
    expect((await events(app, "policy.lifecycle")).map((event) => event.eventType)).toEqual([
      "policy.lifecycle.create",
      "policy.lifecycle.update",
      "policy.lifecycle.deactivate",
      "policy.lifecycle.delete",
    ]);
  });

  it("manages a policy's rules, typed after the policy, and records them with the policy", async () => {
    const app = createTestApp();
    const policy = (await call(app, "POST", "/api/v1/policies", signOnPolicy)).body;
    const rule = await call(app, "POST", `/api/v1/policies/${policy.id}/rules`, mfaRule);
    expect(rule.status).toBe(200);
    expect(rule.body).toMatchObject({
      type: "SIGN_ON",
      status: "ACTIVE",
      name: "Require MFA",
      actions: mfaRule.actions,
    });

    const weakened = {
      ...mfaRule,
      actions: { signon: { access: "ALLOW", requireFactor: false } },
    };
    await call(app, "PUT", `/api/v1/policies/${policy.id}/rules/${rule.body.id}`, weakened);
    await call(app, "POST", `/api/v1/policies/${policy.id}/rules/${rule.body.id}/lifecycle/deactivate`);
    expect((await call(app, "GET", `/api/v1/policies/${policy.id}/rules`)).body).toMatchObject([
      { id: rule.body.id, status: "INACTIVE", actions: weakened.actions },
    ]);
    await call(app, "DELETE", `/api/v1/policies/${policy.id}/rules/${rule.body.id}`);

    const recorded = await events(app, "policy.rule");
    expect(recorded.map((event) => event.eventType)).toEqual([
      "policy.rule.add",
      "policy.rule.update",
      "policy.rule.deactivate",
      "policy.rule.delete",
    ]);
    expect(recorded[1].actor).toMatchObject({ id: "00u_ada" });
    expect(recorded[1]).toMatchObject({
      displayMessage: "Update policy rule",
      legacyEventType: "policy.rule.updated",
      target: [
        { id: policy.id, type: "PolicyEntity", alternateId: "unknown", detailEntry: { policyType: "OktaSignOn" } },
        { id: rule.body.id, type: "PolicyRule", alternateId: policy.id, displayName: "Require MFA" },
      ],
    });
  });

  it("records app sign-in policies and their rules as rule sets", async () => {
    const app = createTestApp();
    const policy = (await call(app, "POST", "/api/v1/policies", { type: "ACCESS_POLICY", name: "Portal sign-in" }))
      .body;
    expect(policy.id).toMatch(/^rst/);
    const rule = (await call(app, "POST", `/api/v1/policies/${policy.id}/rules`, { name: "Off network" })).body;
    expect(rule).toMatchObject({ type: "ACCESS_POLICY" });
    expect(rule.id).toMatch(/^rul/);
    const [add] = await events(app, "policy.rule.add");
    expect(add.target).toMatchObject([
      { id: policy.id, type: "RuleSetEntity", alternateId: "unknown", detailEntry: { policyType: "ACCESS_POLICY" } },
      { id: rule.id, type: "RuleEntity", alternateId: "unknown", displayName: "Off network", detailEntry: null },
    ]);
  });

  it("refuses rules on policies that take none, and policies without a name or a valid type", async () => {
    const app = createTestApp();
    const enrollment = (await call(app, "POST", "/api/v1/policies", { type: "PROFILE_ENROLLMENT", name: "Profile" }))
      .body;
    expect((await call(app, "POST", `/api/v1/policies/${enrollment.id}/rules`, mfaRule)).status).toBe(400);
    expect((await call(app, "POST", "/api/v1/policies", { type: "OKTA_SIGN_ON" })).status).toBe(400);
    expect((await call(app, "POST", "/api/v1/policies", { type: "NOPE", name: "x" })).status).toBe(400);
  });
});

describe("Okta network zones", () => {
  const ipZone = { type: "IP", name: "Clinic offices", gateways: [{ type: "CIDR", value: "203.0.113.0/24" }] };

  it("creates, replaces, deactivates and deletes an IP zone", async () => {
    const app = createTestApp();
    const created = await call(app, "POST", "/api/v1/zones", ipZone);
    expect(created.status).toBe(200);
    expect(created.body).toMatchObject({
      type: "IP",
      name: "Clinic offices",
      status: "ACTIVE",
      usage: "POLICY",
      system: false,
      gateways: ipZone.gateways,
    });
    expect(created.body.id).toMatch(/^nzo/);
    const id = created.body.id;

    const widened = { ...ipZone, gateways: [{ type: "CIDR", value: "0.0.0.0/0" }] };
    expect((await call(app, "PUT", `/api/v1/zones/${id}`, widened)).body.gateways).toEqual(widened.gateways);
    expect((await call(app, "DELETE", `/api/v1/zones/${id}`)).status).toBe(403);
    expect((await call(app, "POST", `/api/v1/zones/${id}/lifecycle/deactivate`)).body.status).toBe("INACTIVE");
    expect((await call(app, "DELETE", `/api/v1/zones/${id}`)).status).toBe(204);

    const recorded = await events(app, "zone.");
    expect(recorded.map((event) => event.eventType)).toEqual([
      "zone.create",
      "zone.update",
      "zone.deactivate",
      "zone.delete",
    ]);
    expect(recorded[1]).toMatchObject({
      displayMessage: "Network zone update",
      legacyEventType: "zone.update",
      actor: { id: "00u_ada" },
      target: [{ id, type: "NetworkZoneEntity", alternateId: "unknown", displayName: "Clinic offices" }],
    });
    expect(JSON.parse(recorded[1].debugContext.debugData.zoneData)).toEqual({ type: "IP", gateways: widened.gateways });
    expect(JSON.parse(recorded[2].debugContext.debugData.zoneData)).toMatchObject({ type: "IP" });
  });

  it("requires addresses for an IP zone and keeps a zone's type", async () => {
    const app = createTestApp();
    expect((await call(app, "POST", "/api/v1/zones", { type: "IP", name: "Empty" })).status).toBe(400);
    const dynamic = await call(app, "POST", "/api/v1/zones", {
      type: "DYNAMIC",
      name: "Blocked countries",
      usage: "BLOCKLIST",
      locations: [{ country: "AQ" }],
    });
    expect(dynamic.body).toMatchObject({ type: "DYNAMIC", usage: "BLOCKLIST", locations: [{ country: "AQ" }] });
    expect((await call(app, "PUT", `/api/v1/zones/${dynamic.body.id}`, ipZone)).status).toBe(400);
  });
});
