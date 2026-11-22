import { describe, expect, it } from "vitest";
import { Hono, Store, WebhookDispatcher, authMiddleware } from "@emulators/core";
import type { TokenMap } from "@emulators/core";
import { getOktaStore, oktaPlugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";
const redirectUri = "http://localhost:3000/callback";
const client = { client_id: "portal", client_secret: "portal-secret" };
const admin = { Authorization: "SSWS admin-token" };

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
      { okta_id: "00u_alice", login: "alice@example.com", first_name: "Alice", last_name: "Doe" },
    ],
    oauth_clients: [{ ...client, name: "Portal", redirect_uris: [redirectUri], auth_server_id: "default" }],
  });
  return { app, store };
}

const authorizeQuery = (extra = "") =>
  `client_id=${client.client_id}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=openid&state=s1${extra}`;

/** Signs alice in on the sign-in page and returns her session cookie. */
async function signIn(app: Hono<any>): Promise<string> {
  const response = await app.request(`${base}/oauth2/default/v1/authorize/callback`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      user_ref: "00u_alice",
      client_id: client.client_id,
      redirect_uri: redirectUri,
      scope: "openid",
    }),
  });
  const setCookie = response.headers.get("set-cookie") ?? "";
  expect(setCookie).toMatch(/^idx=idx[\w-]+; Path=\/; HttpOnly; Secure; SameSite=None$/);
  return setCookie.split(";")[0]!;
}

function authorize(app: Hono<any>, cookie: string | null, extra = "") {
  return app.request(`${base}/oauth2/default/v1/authorize?${authorizeQuery(extra)}`, {
    headers: cookie ? { Cookie: cookie } : {},
  });
}

async function events(app: Hono<any>): Promise<any[]> {
  return (await (await app.request(`${base}/api/v1/logs`, { headers: admin })).json()) as any[];
}

const sessionIdOf = (cookie: string) => cookie.slice("idx=".length);

describe("Okta sessions", () => {
  it("signs the user in silently on an existing session, without a new session start", async () => {
    const { app } = createTestApp();
    const cookie = await signIn(app);

    const silent = await authorize(app, cookie);
    expect(silent.status).toBe(302);
    const location = new URL(silent.headers.get("location") ?? "");
    expect(location.searchParams.get("code")).toBeTruthy();
    expect(location.searchParams.get("state")).toBe("s1");

    const recorded = await events(app);
    expect(recorded.filter((event) => event.eventType === "user.session.start")).toHaveLength(1);
    const codes = recorded.filter((event) => event.eventType.endsWith("authorize.code"));
    expect(codes).toHaveLength(2);
    for (const event of [...recorded.filter((e) => e.eventType === "user.session.start"), ...codes]) {
      expect(event.authenticationContext.externalSessionId).toBe(sessionIdOf(cookie));
    }
  });

  it("shows the sign-in page for prompt=login or a stale max_age, and refuses prompt=none without a session", async () => {
    const { app, store } = createTestApp();
    const cookie = await signIn(app);
    expect((await authorize(app, cookie, "&prompt=login")).status).toBe(200);

    const session = getOktaStore(store).sessions.all()[0]!;
    getOktaStore(store).sessions.update(session.id, {
      authenticated_at: new Date(Date.now() - 600_000).toISOString(),
    });
    expect((await authorize(app, cookie, "&max_age=60")).status).toBe(200);
    expect((await authorize(app, cookie, "&max_age=3600")).status).toBe(302);

    const refused = await authorize(app, null, "&prompt=none");
    const location = new URL(refused.headers.get("location") ?? "");
    expect(location.searchParams.get("error")).toBe("login_required");
    expect(location.searchParams.get("error_description")).toBe(
      "The client specified not to prompt, but the user is not logged in.",
    );
    expect(location.searchParams.get("state")).toBe("s1");
  });

  it("serves, refreshes and revokes a session through the Sessions API", async () => {
    const { app, store } = createTestApp();
    const cookie = await signIn(app);
    const id = sessionIdOf(cookie);

    const fetched = await app.request(`${base}/api/v1/sessions/${id}`, { headers: admin });
    const session = (await fetched.json()) as any;
    expect(session).toMatchObject({
      id,
      userId: "00u_alice",
      login: "alice@example.com",
      status: "ACTIVE",
      amr: ["pwd"],
      idp: { type: "OKTA" },
      _links: { self: { href: `${base}/api/v1/sessions/${id}` } },
    });
    expect(session.idp.id).toMatch(/^00o/);
    expect(Date.parse(session.expiresAt) - Date.parse(session.createdAt)).toBe(120 * 60 * 1000);

    const entry = getOktaStore(store).sessions.all()[0]!;
    getOktaStore(store).sessions.update(entry.id, { last_activity_at: new Date(Date.now() - 3_600_000).toISOString() });
    const refreshed = (await (
      await app.request(`${base}/api/v1/sessions/${id}/lifecycle/refresh`, { method: "POST", headers: admin })
    ).json()) as any;
    expect(Date.parse(refreshed.expiresAt)).toBeGreaterThan(Date.now() + 119 * 60 * 1000);

    expect((await app.request(`${base}/api/v1/sessions/${id}`, { method: "DELETE", headers: admin })).status).toBe(204);
    const gone = await app.request(`${base}/api/v1/sessions/${id}`, { headers: admin });
    expect(gone.status).toBe(404);
    expect(await gone.json()).toMatchObject({
      errorCode: "E0000007",
      errorSummary: `Not found: Resource not found: ${id} (Session)`,
    });
    expect((await authorize(app, cookie)).status).toBe(200);

    const [end] = (await events(app)).filter((event) => event.eventType === "user.session.end");
    expect(end).toMatchObject({
      actor: { id: "00u_ada" },
      target: [{ id: "00u_alice" }],
    });
  });

  it("expires a session after its idle time", async () => {
    const { app, store } = createTestApp();
    const cookie = await signIn(app);
    const entry = getOktaStore(store).sessions.all()[0]!;
    getOktaStore(store).sessions.update(entry.id, {
      last_activity_at: new Date(Date.now() - 121 * 60 * 1000).toISOString(),
    });
    expect((await authorize(app, cookie)).status).toBe(200);
    expect((await app.request(`${base}/api/v1/sessions/${sessionIdOf(cookie)}`, { headers: admin })).status).toBe(404);
  });

  it("revokes all of a user's sessions, one session end each, then the clear", async () => {
    const { app } = createTestApp();
    const first = await signIn(app);
    const second = await signIn(app);

    const cleared = await app.request(`${base}/api/v1/users/00u_alice/sessions`, { method: "DELETE", headers: admin });
    expect(cleared.status).toBe(204);
    expect((await authorize(app, first)).status).toBe(200);
    expect((await authorize(app, second)).status).toBe(200);

    const recorded = (await events(app)).filter((event) => event.eventType.startsWith("user.session.")).slice(2);
    expect(recorded.map((event) => event.eventType)).toEqual([
      "user.session.end",
      "user.session.end",
      "user.session.clear",
    ]);
    for (const event of recorded)
      expect(event.debugContext.debugData.requestUri).toBe("/api/v1/users/00u_alice/sessions");
    expect(new Set(recorded.map((event) => event.transaction.id)).size).toBe(1);
  });

  it("ends the sessions of a deactivated user", async () => {
    const { app } = createTestApp();
    const cookie = await signIn(app);
    await app.request(`${base}/api/v1/users/00u_alice/lifecycle/deactivate`, { method: "POST", headers: admin });
    expect((await authorize(app, cookie)).status).toBe(200);
    const recorded = (await events(app)).map((event) => event.eventType);
    expect(recorded.slice(-3)).toEqual(["user.lifecycle.deactivate", "user.session.end", "user.session.clear"]);
  });

  it("ends the sessions of a suspended user", async () => {
    const { app } = createTestApp();
    const cookie = await signIn(app);
    await app.request(`${base}/api/v1/users/00u_alice/lifecycle/suspend`, { method: "POST", headers: admin });
    await app.request(`${base}/api/v1/users/00u_alice/lifecycle/unsuspend`, { method: "POST", headers: admin });
    expect((await authorize(app, cookie)).status).toBe(200);
    const recorded = (await events(app)).map((event) => event.eventType);
    expect(recorded.slice(-4)).toEqual([
      "user.lifecycle.suspend",
      "user.session.end",
      "user.session.clear",
      "user.lifecycle.unsuspend",
    ]);
  });

  it("ends the session at logout, keeps the tokens, and clears the cookie", async () => {
    const { app } = createTestApp();
    const callback = await app.request(`${base}/oauth2/default/v1/authorize/callback`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        user_ref: "00u_alice",
        client_id: client.client_id,
        redirect_uri: redirectUri,
        scope: "openid",
      }),
    });
    const cookie = (callback.headers.get("set-cookie") ?? "").split(";")[0]!;
    const code = new URL(callback.headers.get("location") ?? "").searchParams.get("code") ?? "";
    const tokens = (await (
      await app.request(`${base}/oauth2/default/v1/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ ...client, grant_type: "authorization_code", code, redirect_uri: redirectUri }),
      })
    ).json()) as { id_token: string; access_token: string };

    const logout = await app.request(`${base}/oauth2/default/v1/logout?id_token_hint=${tokens.id_token}`, {
      headers: { Cookie: cookie },
    });
    expect(logout.headers.get("set-cookie")).toContain("idx=;");
    expect((await authorize(app, cookie)).status).toBe(200);
    const userinfo = await app.request(`${base}/oauth2/default/v1/userinfo`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(userinfo.status).toBe(200);

    const [end] = (await events(app)).filter((event) => event.eventType === "user.session.end");
    expect(end).toMatchObject({
      actor: { id: "00u_alice" },
      authenticationContext: { externalSessionId: sessionIdOf(cookie) },
    });
  });
});
