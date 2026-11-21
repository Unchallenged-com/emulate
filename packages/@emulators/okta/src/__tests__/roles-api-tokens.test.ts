import { describe, expect, it } from "vitest";
import { Hono, Store, WebhookDispatcher, authMiddleware } from "@emulators/core";
import type { TokenMap } from "@emulators/core";
import { getOktaStore, oktaPlugin, seedFromConfig, type OktaSeedConfig } from "../index.js";

const base = "http://localhost:4000";
const json = { "Content-Type": "application/json" };
const ada = { Authorization: "SSWS ada-token", ...json };
const eve = { Authorization: "SSWS eve-token", ...json };

const seed: OktaSeedConfig = {
  users: [
    { okta_id: "00u_ada", login: "ada@example.com", first_name: "Ada", last_name: "Admin" },
    { okta_id: "00u_eve", login: "eve@example.com", first_name: "Eve", last_name: "Ops" },
    { okta_id: "00u_bob", login: "bob@example.com", first_name: "Bob", last_name: "Roe" },
  ],
  role_assignments: [{ user_okta_id: "00u_ada", type: "SUPER_ADMIN" }],
  api_tokens: [
    { token: "ada-token", name: "Ada automation", user_okta_id: "00u_ada", id: "00T_ada" },
    { token: "eve-token", name: "Eve sync", user_okta_id: "00u_eve", id: "00T_eve" },
  ],
};

function createTestApp(config: OktaSeedConfig = seed, fallback = true) {
  const tokenMap: TokenMap = new Map();
  const app = new Hono();
  app.use(
    "*",
    authMiddleware(tokenMap, undefined, fallback ? { login: "bob@example.com", id: 3, scopes: [] } : undefined),
  );
  const store = new Store();
  oktaPlugin.register(app as any, store, new WebhookDispatcher(), base, tokenMap);
  oktaPlugin.seed?.(store, base);
  seedFromConfig(store, base, config);
  return { app, store };
}

async function call(app: Hono<any>, method: string, path: string, headers = ada, body?: unknown) {
  const response = await app.request(`${base}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

async function events(app: Hono<any>, eventTypePrefix: string): Promise<any[]> {
  const filter = encodeURIComponent(`eventType sw "${eventTypePrefix}"`);
  return (await call(app, "GET", `/api/v1/logs?filter=${filter}`)).body;
}

describe("Okta role assignments", () => {
  it("lists, assigns, retrieves and unassigns standard roles", async () => {
    const { app } = createTestApp();
    const listed = await call(app, "GET", "/api/v1/users/00u_ada/roles");
    expect(listed.status).toBe(200);
    expect(listed.body).toMatchObject([{ type: "SUPER_ADMIN", label: "Super Administrator", status: "ACTIVE" }]);

    const assigned = await call(app, "POST", "/api/v1/users/00u_bob/roles", ada, { type: "HELP_DESK_ADMIN" });
    expect(assigned.status).toBe(201);
    expect(assigned.body).toMatchObject({
      type: "HELP_DESK_ADMIN",
      label: "Help Desk Administrator",
      status: "ACTIVE",
      assignmentType: "USER",
      _links: { assignee: { href: `${base}/api/v1/users/00u_bob` } },
    });
    expect(assigned.body.id).toMatch(/^ra/);

    const fetched = await call(app, "GET", `/api/v1/users/00u_bob/roles/${assigned.body.id}`);
    expect(fetched.body).toEqual(assigned.body);

    expect((await call(app, "DELETE", `/api/v1/users/00u_bob/roles/${assigned.body.id}`)).status).toBe(204);
    expect((await call(app, "GET", "/api/v1/users/00u_bob/roles")).body).toEqual([]);
    expect((await call(app, "GET", `/api/v1/users/00u_bob/roles/${assigned.body.id}`)).status).toBe(404);
  });

  it("refuses a duplicate role and an unknown role type", async () => {
    const { app } = createTestApp();
    const duplicate = await call(app, "POST", "/api/v1/users/00u_ada/roles", ada, { type: "SUPER_ADMIN" });
    expect(duplicate.status).toBe(409);
    expect(duplicate.body).toMatchObject({
      errorCode: "E0000090",
      errorSummary: "The role specified is already assigned to the user.",
    });
    const unknown = await call(app, "POST", "/api/v1/users/00u_bob/roles", ada, { type: "KING" });
    expect(unknown.status).toBe(400);
    expect(unknown.body.errorCode).toBe("E0000001");
    expect((await call(app, "POST", "/api/v1/users/00u_nobody/roles", ada, { type: "APP_ADMIN" })).status).toBe(404);
  });

  it("records privilege grants with the roles held, and the revocation of the last one", async () => {
    const { app } = createTestApp();
    const first = await call(app, "POST", "/api/v1/users/00u_bob/roles", ada, { type: "APP_ADMIN" });
    const second = await call(app, "POST", "/api/v1/users/00u_bob/roles", ada, { type: "ORG_ADMIN" });
    await call(app, "DELETE", `/api/v1/users/00u_bob/roles/${first.body.id}`);
    await call(app, "DELETE", `/api/v1/users/00u_bob/roles/${second.body.id}`);

    const recorded = await events(app, "user.account.privilege");
    expect(recorded.map((event) => [event.eventType, event.debugContext.debugData.privilegeGranted])).toEqual([
      ["user.account.privilege.grant", "Application administrator (all)"],
      ["user.account.privilege.grant", "Application administrator (all), Organization administrator"],
      ["user.account.privilege.grant", "Organization administrator"],
      ["user.account.privilege.revoke", undefined],
    ]);
    expect(recorded[3].debugContext.debugData.privilegeRevoked).toBe("Organization administrator");
    expect(recorded[3].displayMessage).toBe("Revoke user privilege");
    expect(recorded[0]).toMatchObject({
      displayMessage: "Grant user privilege",
      legacyEventType: "core.user.admin_privilege.granted",
    });
    expect(recorded[0]).toMatchObject({
      actor: { id: "00u_ada", type: "User", alternateId: "ada@example.com" },
      target: [{ id: "00u_bob", type: "User", alternateId: "bob@example.com" }],
      transaction: { detail: { requestApiTokenId: "00T_ada" } },
    });
  });
});

describe("Okta API tokens", () => {
  it("lists and retrieves the metadata of active tokens", async () => {
    const { app } = createTestApp();
    const listed = await call(app, "GET", "/api/v1/api-tokens");
    expect(listed.body.map((token: any) => token.id)).toEqual(["00T_ada", "00T_eve"]);
    expect(listed.body[0]).toMatchObject({
      name: "Ada automation",
      userId: "00u_ada",
      tokenWindow: "P30D",
      network: { connection: "ANYWHERE" },
      clientName: "Okta API",
      _links: { self: { href: `${base}/api/v1/api-tokens/00T_ada` }, user: { href: `${base}/api/v1/users/00u_ada` } },
    });
    expect(JSON.stringify(listed.body)).not.toContain("ada-token");
    expect((await call(app, "GET", "/api/v1/api-tokens/00T_eve")).body.name).toBe("Eve sync");
    expect((await call(app, "GET", "/api/v1/api-tokens/00T_none")).status).toBe(404);
  });

  it("acts as the token's user, and refuses a revoked token in permissive mode", async () => {
    const { app } = createTestApp();
    await call(app, "POST", "/api/v1/users/00u_bob/lifecycle/suspend", eve);
    const [suspend] = await events(app, "user.lifecycle.suspend");
    expect(suspend.actor.alternateId).toBe("eve@example.com");

    expect((await call(app, "DELETE", "/api/v1/api-tokens/00T_eve")).status).toBe(204);
    const refused = await call(app, "GET", "/api/v1/users", eve);
    expect(refused.status).toBe(401);
    expect(refused.body).toMatchObject({ errorCode: "E0000011", errorSummary: "Invalid token provided" });
    expect((await call(app, "GET", "/api/v1/api-tokens")).body.map((token: any) => token.id)).toEqual(["00T_ada"]);

    const [revoke] = await events(app, "system.api_token");
    expect(revoke).toMatchObject({
      eventType: "system.api_token.revoke",
      displayMessage: "Revoke API token",
      legacyEventType: "api.token.revoke",
      debugContext: { debugData: { networkConnection: "ANYWHERE" } },
      actor: { id: "00u_ada" },
      target: [{ id: "00T_eve", type: "Token", alternateId: "unknown", displayName: "Eve sync" }],
    });
  });

  it("revokes the calling token at /api/v1/api-tokens/current", async () => {
    const { app } = createTestApp();
    expect((await call(app, "DELETE", "/api/v1/api-tokens/current", eve)).status).toBe(204);
    expect((await call(app, "GET", "/api/v1/users", eve)).status).toBe(401);
    expect((await call(app, "GET", "/api/v1/users", ada)).status).toBe(200);
  });

  it("deprovisions a user's tokens when the user is deactivated", async () => {
    const { app } = createTestApp();
    await call(app, "POST", "/api/v1/users/00u_eve/lifecycle/deactivate");
    expect((await call(app, "GET", "/api/v1/users", eve)).status).toBe(401);
    expect((await call(app, "GET", "/api/v1/api-tokens")).body.map((token: any) => token.id)).toEqual(["00T_ada"]);
  });

  it("refuses a token unused for 30 days", async () => {
    const { app, store } = createTestApp();
    const token = getOktaStore(store).apiTokens.findOneBy("token_id", "00T_eve")!;
    const longAgo = new Date(Date.now() - 31 * 24 * 3600 * 1000).toISOString();
    getOktaStore(store).apiTokens.update(token.id, { last_used_at: longAgo });
    expect((await call(app, "GET", "/api/v1/users", eve)).status).toBe(401);
  });

  it("accepts seeded API tokens in strict mode", async () => {
    const { app } = createTestApp({ ...seed, strict_scopes: true }, false);
    expect((await call(app, "GET", "/api/v1/users", eve)).status).toBe(200);
    expect((await call(app, "GET", "/api/v1/users", { Authorization: "SSWS unknown", ...json })).status).toBe(401);
  });
});
