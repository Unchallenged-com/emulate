import { describe, expect, it } from "vitest";
import { Hono, Store, WebhookDispatcher, authMiddleware, setClientAddress } from "@emulators/core";
import type { TokenMap } from "@emulators/core";
import { oktaPlugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";
const redirectUri = "http://localhost:3000/callback";
const client = { client_id: "0oa_portal", client_secret: "portal-secret" };
const service = { client_id: "0oa_service", client_secret: "service-secret" };
const json = { "Content-Type": "application/json" };
const admin = {
  Authorization: "SSWS admin-token",
  "User-Agent": "okta-sdk-python/2.9.13 python/3.13.11 Linux/6.8.0",
  ...json,
};
const browser =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36";

function createTestApp() {
  const tokenMap: TokenMap = new Map([["admin-token", { login: "admin@example.com", id: 1, scopes: ["okta.*"] }]]);
  const app = new Hono();
  app.use("*", authMiddleware(tokenMap));
  const store = new Store();
  oktaPlugin.register(app as any, store, new WebhookDispatcher(), base, tokenMap);
  oktaPlugin.seed?.(store, base);
  seedFromConfig(store, base, {
    users: [
      { okta_id: "00u_admin", login: "admin@example.com", first_name: "Ada", last_name: "Admin" },
      { okta_id: "00u_alice", login: "alice@example.com", first_name: "Alice", last_name: "Doe" },
      { okta_id: "00u_bob", login: "bob@example.com", first_name: "Bob", last_name: "Roe" },
    ],
    groups: [{ okta_id: "00g_staff", name: "Staff" }],
    apps: [
      {
        okta_id: "0oa_app",
        name: "portal",
        label: "Portal",
        credentials: { oauthClient: { client_id: client.client_id } },
      },
    ],
    oauth_clients: [
      { ...client, name: "Portal", redirect_uris: [redirectUri], auth_server_id: "default" },
      { ...service, name: "IDP Updater", redirect_uris: [], auth_server_id: "org" },
    ],
    app_assignments: [{ app_okta_id: "0oa_app", user_okta_id: "00u_alice" }],
  });
  return app;
}

function from(address: string, url: string, init: RequestInit = {}): Request {
  const request = new Request(url, init);
  setClientAddress(request, address);
  return request;
}

async function events(app: Hono<any>, filter?: string): Promise<any[]> {
  const query = filter ? `?filter=${encodeURIComponent(filter)}` : "";
  return (await (await app.request(`${base}/api/v1/logs${query}`, { headers: admin })).json()) as any[];
}

function form(body: Record<string, string>, headers: Record<string, string> = {}): RequestInit {
  return {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
    body: new URLSearchParams(body),
  };
}

describe("Okta System Log events", () => {
  it("records an administrator's API call with its actor, token, client and target", async () => {
    const app = createTestApp();
    await app.request(
      from("203.0.113.7", `${base}/api/v1/users/00u_bob/lifecycle/suspend`, { method: "POST", headers: admin }),
    );

    const [event] = await events(app);
    expect(Object.keys(event)).toEqual([
      "actor",
      "client",
      "device",
      "authenticationContext",
      "displayMessage",
      "eventType",
      "outcome",
      "published",
      "securityContext",
      "severity",
      "debugContext",
      "legacyEventType",
      "transaction",
      "uuid",
      "version",
      "request",
      "target",
    ]);
    expect(event).toMatchObject({
      eventType: "user.lifecycle.suspend",
      displayMessage: "Suspend Okta user",
      severity: "INFO",
      version: "0",
      outcome: { result: "SUCCESS", reason: null },
      actor: { id: "00u_admin", type: "User", alternateId: "admin@example.com", displayName: "Ada Admin" },
      client: {
        ipAddress: "203.0.113.7",
        zone: "null",
        device: "Unknown",
        userAgent: { rawUserAgent: admin["User-Agent"], browser: "UNKNOWN", os: "Linux" },
      },
      transaction: { type: "WEB", detail: { requestApiTokenId: expect.stringMatching(/^00T/) } },
      request: { ipChain: [{ ip: "203.0.113.7", version: "V4" }] },
      target: [{ id: "00u_bob", type: "User", alternateId: "bob@example.com", displayName: "Bob Roe" }],
    });
    expect(event.authenticationContext.externalSessionId).toMatch(/^trs/);
    expect(event.debugContext.debugData).toMatchObject({
      requestId: event.transaction.id,
      requestUri: "/api/v1/users/00u_bob/lifecycle/suspend",
    });
  });

  it("records user lifecycle changes and the steps of a hard delete", async () => {
    const app = createTestApp();
    await app.request(`${base}/api/v1/groups/00g_staff/users/00u_bob`, { method: "PUT", headers: admin });
    await app.request(`${base}/api/v1/users/00u_bob`, { method: "DELETE", headers: admin });
    await app.request(`${base}/api/v1/users/00u_bob`, { method: "DELETE", headers: admin });

    const recorded = await events(app);
    expect(recorded.map((event) => event.eventType)).toEqual([
      "group.user_membership.add",
      "user.lifecycle.deactivate",
      "user.lifecycle.delete.initiated",
      "group.user_membership.remove",
      "user.lifecycle.delete.completed",
    ]);
    expect(recorded[0].target.map((target: any) => target.type)).toEqual(["User", "UserGroup"]);
    expect(recorded[0].target[1]).toMatchObject({ id: "00g_staff", alternateId: "unknown", displayName: "Staff" });
    expect(recorded[4].target[0]).toMatchObject({ id: "00u_bob", alternateId: "00u_bob" });
    expect(recorded[4].legacyEventType).toBe("core.user.config.user_status.delete.completed");
    expect(new Set(recorded.slice(2).map((event) => event.transaction.id)).size).toBe(1);
  });

  it("records user creation, activation, profile updates and session clearing", async () => {
    const app = createTestApp();
    const created = await app.request(`${base}/api/v1/users?activate=true`, {
      method: "POST",
      headers: admin,
      body: JSON.stringify({ profile: { login: "carol@example.com", email: "carol@example.com" } }),
    });
    const { id } = (await created.json()) as { id: string };
    await app.request(`${base}/api/v1/users/${id}`, {
      method: "POST",
      headers: admin,
      body: JSON.stringify({ profile: { lastName: "Smith" } }),
    });
    await app.request(`${base}/api/v1/users/${id}/sessions`, { method: "DELETE", headers: admin });

    const recorded = await events(app, `target.id eq "${id}"`);
    expect(recorded.map((event) => event.eventType)).toEqual([
      "user.lifecycle.create",
      "user.lifecycle.activate",
      "user.account.update_profile",
      "user.session.clear",
    ]);
  });

  it("records group and app changes with Okta's targets", async () => {
    const app = createTestApp();
    const group = await app.request(`${base}/api/v1/groups`, {
      method: "POST",
      headers: admin,
      body: JSON.stringify({ profile: { name: "Nurses" } }),
    });
    const { id: groupId } = (await group.json()) as { id: string };
    await app.request(`${base}/api/v1/groups/${groupId}`, {
      method: "PUT",
      headers: admin,
      body: JSON.stringify({ profile: { name: "Nurses", description: "Ward staff" } }),
    });
    await app.request(`${base}/api/v1/groups/${groupId}`, { method: "DELETE", headers: admin });
    await app.request(`${base}/api/v1/apps/0oa_app/users/00u_bob`, { method: "PUT", headers: admin });
    await app.request(`${base}/api/v1/apps/0oa_app/users/00u_bob`, { method: "DELETE", headers: admin });
    await app.request(`${base}/api/v1/apps/0oa_app/lifecycle/deactivate`, { method: "POST", headers: admin });

    const recorded = await events(app);
    expect(recorded.map((event) => event.eventType)).toEqual([
      "group.lifecycle.create",
      "group.profile.update",
      "group.lifecycle.delete",
      "application.user_membership.add",
      "application.user_membership.remove",
      "application.lifecycle.deactivate",
    ]);
    expect(recorded[2]).toMatchObject({
      displayMessage: "Delete okta group",
      legacyEventType: "group.lifecycle.delete",
    });
    expect(recorded[3].target.map((target: any) => [target.type, target.alternateId])).toEqual([
      ["AppUser", "bob@example.com"],
      ["AppInstance", "Portal"],
      ["User", "bob@example.com"],
    ]);
    expect(recorded[3].legacyEventType).toBe("app.generic.provision.assign_user_to_app");
  });

  it("records nothing for a request that changes nothing", async () => {
    const app = createTestApp();
    await app.request(`${base}/api/v1/apps/0oa_app/users/00u_alice`, { method: "PUT", headers: admin });
    await app.request(`${base}/api/v1/groups/00g_staff/users/00u_bob`, { method: "DELETE", headers: admin });
    await app.request(`${base}/api/v1/users/00u_unknown/lifecycle/suspend`, { method: "POST", headers: admin });
    expect(await events(app)).toEqual([]);
  });

  it("records a sign-in and the single sign-on to the app with one session", async () => {
    const app = createTestApp();
    const callback = await app.request(
      from(
        "198.51.100.20",
        `${base}/oauth2/default/v1/authorize/callback`,
        form(
          { user_ref: "00u_alice", client_id: client.client_id, redirect_uri: redirectUri, scope: "openid" },
          { "User-Agent": browser },
        ),
      ),
    );
    const code = new URL(callback.headers.get("location") ?? "").searchParams.get("code") ?? "";
    await app.request(
      `${base}/oauth2/default/v1/token`,
      form({ ...client, grant_type: "authorization_code", code, redirect_uri: redirectUri }),
    );

    const recorded = await events(app);
    expect(recorded.map((event) => event.eventType)).toEqual([
      "user.session.start",
      "app.oauth2.as.authorize.code",
      "user.authentication.sso",
      "app.oauth2.as.token.grant.access_token",
      "app.oauth2.as.token.grant.id_token",
      "app.oauth2.as.token.grant.refresh_token",
    ]);
    const [start, , sso] = recorded;
    expect(start).toMatchObject({
      eventType: "user.session.start",
      displayMessage: "User login to Okta",
      legacyEventType: "core.user_auth.login_success",
      actor: { id: "00u_alice", type: "User", alternateId: "alice@example.com" },
      client: { ipAddress: "198.51.100.20", device: "Computer", userAgent: { browser: "CHROME", os: "Mac OS X" } },
      transaction: { detail: {} },
      target: [{ id: "0oa_app", type: "AppInstance", alternateId: "Portal" }],
    });
    expect(start.authenticationContext.externalSessionId).toMatch(/^idx/);
    expect(sso).toMatchObject({
      eventType: "user.authentication.sso",
      displayMessage: "User single sign on to app",
      legacyEventType: "app.auth.sso",
      client: { id: client.client_id },
      authenticationContext: { externalSessionId: start.authenticationContext.externalSessionId },
      debugContext: { debugData: { signOnMode: "OpenID Connect", requestUri: "/oauth2/default/v1/token" } },
      target: [
        { type: "AppInstance", id: "0oa_app", detailEntry: { signOnModeType: "OPENID_CONNECT" } },
        { type: "AppUser", id: "00u_alice", alternateId: "alice@example.com" },
      ],
    });
  });

  it("records the sign-in of a user the app then refuses, and the unauthorized access attempt", async () => {
    const app = createTestApp();
    const callback = await app.request(
      `${base}/oauth2/default/v1/authorize/callback`,
      form({ user_ref: "00u_bob", client_id: client.client_id, redirect_uri: redirectUri, scope: "openid" }),
    );
    expect(callback.headers.get("location")).toContain("error=access_denied");
    const [start, attempt, ...rest] = await events(app);
    expect(rest).toEqual([]);
    expect(start.eventType).toBe("user.session.start");
    expect(attempt).toMatchObject({
      eventType: "app.generic.unauth_app_access_attempt",
      displayMessage: "User attempted unauthorized access to app",
      legacyEventType: "app.generic.unauth_app_access_attempt",
      severity: "WARN",
      outcome: { result: "FAILURE", reason: null },
      actor: { id: "00u_bob", type: "User" },
      authenticationContext: {
        externalSessionId: start.authenticationContext.externalSessionId,
        rootSessionId: start.authenticationContext.externalSessionId,
      },
      target: [{ id: "0oa_app", type: "AppInstance", alternateId: "Portal", displayName: "Portal" }],
    });
  });

  it("records a logout with the user and session of the ID token hint", async () => {
    const app = createTestApp();
    const callback = await app.request(
      `${base}/oauth2/default/v1/authorize/callback`,
      form({ user_ref: "00u_alice", client_id: client.client_id, redirect_uri: redirectUri, scope: "openid" }),
    );
    const code = new URL(callback.headers.get("location") ?? "").searchParams.get("code") ?? "";
    const tokens = (await (
      await app.request(
        `${base}/oauth2/default/v1/token`,
        form({ ...client, grant_type: "authorization_code", code, redirect_uri: redirectUri }),
      )
    ).json()) as { id_token: string };

    await app.request(`${base}/oauth2/default/v1/logout?id_token_hint=forged`);
    await app.request(`${base}/oauth2/default/v1/logout?id_token_hint=${tokens.id_token}`);

    const recorded = await events(app);
    const end = recorded.at(-1);
    expect(recorded.filter((event) => event.eventType === "user.session.end")).toHaveLength(1);
    expect(end).toMatchObject({
      eventType: "user.session.end",
      displayMessage: "User logout from Okta",
      legacyEventType: "core.user_auth.logout_success",
      actor: { id: "00u_alice", type: "User" },
      authenticationContext: { externalSessionId: recorded[0].authenticationContext.externalSessionId },
      target: [{ id: "00u_alice", type: "User", alternateId: "alice@example.com" }],
    });
  });

  it("records the authorization code request, each token granted, and revocations", async () => {
    const app = createTestApp();
    const callback = await app.request(
      `${base}/oauth2/default/v1/authorize/callback`,
      form({
        user_ref: "00u_alice",
        client_id: client.client_id,
        redirect_uri: redirectUri,
        scope: "openid offline_access",
      }),
    );
    const code = new URL(callback.headers.get("location") ?? "").searchParams.get("code") ?? "";
    const tokens = (await (
      await app.request(
        `${base}/oauth2/default/v1/token`,
        form({ ...client, grant_type: "authorization_code", code, redirect_uri: redirectUri }),
      )
    ).json()) as { access_token: string; refresh_token: string };
    await app.request(
      `${base}/oauth2/default/v1/token`,
      form({ ...client, grant_type: "refresh_token", refresh_token: tokens.refresh_token }),
    );
    await app.request(`${base}/oauth2/default/v1/revoke`, form({ ...client, token: tokens.access_token }));
    await app.request(`${base}/oauth2/default/v1/revoke`, form({ ...client, token: "never-issued" }));

    const recorded = (await events(app)).filter((event) => event.eventType.startsWith("app.oauth2"));
    expect(recorded.map((event) => [event.eventType, event.debugContext.debugData.grantType])).toEqual([
      ["app.oauth2.as.authorize.code", "authorization_code"],
      ["app.oauth2.as.token.grant.access_token", "authorization_code"],
      ["app.oauth2.as.token.grant.id_token", "authorization_code"],
      ["app.oauth2.as.token.grant.refresh_token", "authorization_code"],
      ["app.oauth2.as.token.grant.access_token", "refresh_token"],
      ["app.oauth2.as.token.grant.id_token", "refresh_token"],
      ["app.oauth2.as.token.grant.refresh_token", "refresh_token"],
      ["app.oauth2.as.token.revoke", undefined],
    ]);
    const [authorize, access, id, , , , , revoke] = recorded;
    expect(authorize).toMatchObject({
      displayMessage: "OAuth2 authorization code request",
      legacyEventType: "app.oauth2.as.authorize.code_success",
      actor: { id: client.client_id, type: "PublicClientApp", alternateId: client.client_id, displayName: "Portal" },
      client: { id: client.client_id },
      target: [
        { id: "00u_alice", type: "User", alternateId: null, displayName: null },
        { type: "code", displayName: "Authorization Code" },
      ],
      debugContext: {
        debugData: {
          responseType: "code",
          redirectUri,
          requestedScopes: "openid, offline_access",
          userId: "00u_alice",
          authorizationServer: "default",
          authorizationServerName: "default",
        },
      },
    });
    expect(authorize.authenticationContext.externalSessionId).toMatch(/^idx/);
    expect(access).toMatchObject({
      displayMessage: "OAuth2 access token is granted",
      legacyEventType: "app.oauth2.as.token.grant.access_token_success",
      actor: { type: "PublicClientApp", alternateId: client.client_id },
      authenticationContext: { externalSessionId: "unknown" },
      debugContext: { debugData: { clientAuthType: "client_secret_post", requestedScopes: "", redirectUri } },
      target: [
        { id: "00u_alice", type: "User" },
        { type: "access_token", displayName: "Access Token", detailEntry: { subject: "00u_alice" } },
      ],
    });
    expect(access.debugContext.debugData.authCode).toBe(authorize.target[1].id);
    expect(access.target[1].id).toMatch(/^AT\./);
    expect(id).toMatchObject({
      displayMessage: "OAuth 2.0 ID token is granted",
      target: [
        { type: "User" },
        { type: "id_token", displayName: "ID Token", detailEntry: { audience: client.client_id } },
      ],
    });
    expect(id.target[1].id).toMatch(/^ID\./);
    expect(revoke).toMatchObject({
      displayMessage: "OAuth2 token revocation request",
      legacyEventType: "app.oauth2.as.token.revoke_success",
      client: { id: null },
      target: [{ id: access.target[1].id, type: "access_token", detailEntry: { subject: "00u_alice" } }],
    });
  });

  it("records authorization server changes", async () => {
    const app = createTestApp();
    await app.request(`${base}/api/v1/authorizationServers`, {
      method: "POST",
      headers: admin,
      body: JSON.stringify({ id: "patients", name: "Patients API", description: "Patient records" }),
    });
    await app.request(`${base}/api/v1/authorizationServers/patients/lifecycle/deactivate`, {
      method: "POST",
      headers: admin,
    });
    await app.request(`${base}/api/v1/authorizationServers/patients`, { method: "DELETE", headers: admin });

    const recorded = await events(app, 'eventType sw "oauth2.as."');
    expect(recorded.map((event) => event.eventType)).toEqual([
      "oauth2.as.created",
      "oauth2.as.deactivated",
      "oauth2.as.deleted",
    ]);
    expect(recorded[0]).toMatchObject({
      displayMessage: "Authorization server is created.",
      legacyEventType: "api.oauth2.as.created",
      actor: { id: "00u_admin" },
      target: [
        {
          id: "patients",
          type: "AuthorizationServerEntity",
          alternateId: "unknown",
          displayName: "Patients API",
          detailEntry: { authorizationserverdescription: "Patient records" },
        },
      ],
      debugContext: { debugData: { defaultAuthorizationServer: "false" } },
    });
  });

  it("records a client credentials grant, and the service app as the actor of its API calls", async () => {
    const app = createTestApp();
    const token = await app.request(
      `${base}/oauth2/v1/token`,
      form(
        { grant_type: "client_credentials", scope: "okta.users.manage" },
        {
          Authorization: `Basic ${Buffer.from(`${service.client_id}:${service.client_secret}`).toString("base64")}`,
        },
      ),
    );
    expect(token.status).toBe(200);
    const { access_token } = (await token.json()) as { access_token: string };
    await app.request(`${base}/api/v1/users/00u_bob/lifecycle/suspend`, {
      method: "POST",
      headers: { Authorization: `Bearer ${access_token}` },
    });

    const [grant, suspend] = await events(app);
    expect(grant).toMatchObject({
      eventType: "app.oauth2.token.grant.access_token",
      displayMessage: "OIDC access token is granted",
      legacyEventType: "app.oauth2.token.grant.access_token_success",
      actor: { type: "PublicClientApp", alternateId: service.client_id, displayName: "IDP Updater" },
      authenticationContext: { externalSessionId: "unknown", rootSessionId: "unknown" },
      debugContext: {
        debugData: {
          grantType: "client_credentials",
          clientAuthType: "client_secret_basic",
          requestedScopes: "okta.users.manage",
          grantedScopes: "okta.users.manage",
        },
      },
      target: [{ type: "access_token", alternateId: null, displayName: "Access Token" }],
    });
    expect(grant.target[0].id).toMatch(/^AT\./);
    expect(grant.target[0].detailEntry.hash).toHaveLength(22);
    expect(suspend).toMatchObject({
      eventType: "user.lifecycle.suspend",
      actor: { type: "PublicClientAppEntity", alternateId: "unknown", displayName: "IDP Updater" },
      transaction: {
        detail: {
          requestApiTokenClientId: service.client_id,
          requestApiTokenId: grant.target[0].id,
          rootApiTokenId: grant.target[0].id,
        },
      },
    });
  });
});
