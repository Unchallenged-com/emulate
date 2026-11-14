import { describe, expect, it } from "vitest";
import { Hono, Store, WebhookDispatcher, authMiddleware, type AppEnv, type TokenMap } from "@emulators/core";
import { googlePlugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";
const directory = "/admin/directory/v1";
const scope = (name: string) => `https://www.googleapis.com/auth/${name}`;
const security = scope("admin.directory.user.security");
const redirectUri = "http://127.0.0.1:8080/";
const clients = {
  admin: { client_id: "admin-client", client_secret: "admin-secret", name: "Directory sync" },
  mail: { client_id: "mail-client", client_secret: "mail-secret", name: "Mail reader" },
  drive: { client_id: "drive-client", client_secret: "drive-secret", name: "Drive backup" },
};
const admin = "admin@clinic.example";
const staff = "staff@clinic.example";
const other = "other@clinic.example";

type Client = keyof typeof clients;
type Grant = { access_token: string; refresh_token: string };

function fixture() {
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
      { email: other, name: "Olga Other" },
    ],
    oauth_clients: Object.values(clients).map((client) => ({ ...client, redirect_uris: [redirectUri] })),
  });

  const form = (path: string, body: Record<string, string>) =>
    app.request(`${base}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body).toString(),
    });

  async function grant(email: string, client: Client, scopes: string[]): Promise<Grant> {
    const { client_id, client_secret } = clients[client];
    const authorize = await form("/o/oauth2/v2/auth/callback", {
      email,
      redirect_uri: redirectUri,
      scope: scopes.join(" "),
      client_id,
    });
    const code = new URL(authorize.headers.get("Location")!).searchParams.get("code")!;
    const exchange = await form("/oauth2/token", {
      client_id,
      client_secret,
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
    });
    expect(exchange.status).toBe(200);
    return (await exchange.json()) as Grant;
  }

  const request = (path: string, token: string, method = "GET") =>
    app.request(`${base}${path}`, { method, headers: { Authorization: `Bearer ${token}` } });

  async function works(issued: Grant, client: Client): Promise<boolean> {
    const { client_id, client_secret } = clients[client];
    const refreshed = await form("/oauth2/token", {
      client_id,
      client_secret,
      grant_type: "refresh_token",
      refresh_token: issued.refresh_token,
    });
    const access = await request("/oauth2/v2/userinfo", issued.access_token);
    expect(access.status === 200, "access and refresh tokens agree").toBe(refreshed.status === 200);
    return access.status === 200;
  }

  const adminToken = async (scopes = [scope("admin.directory.user"), security]) =>
    (await grant(admin, "admin", scopes)).access_token;

  return { app, grant, request, works, adminToken };
}

describe("Google Directory API tokens", () => {
  it("lists one token per client the user granted, with the scopes of all its grants", async () => {
    const { grant, request, adminToken } = fixture();
    await grant(staff, "mail", ["openid", "https://mail.google.com/"]);
    await grant(staff, "mail", ["email"]);
    await grant(staff, "drive", [scope("drive")]);
    await grant(other, "drive", [scope("drive.readonly")]);
    const auth = await adminToken();

    const user = (await (await request(`${directory}/users/${staff}`, auth)).json()) as { id: string };
    const response = await request(`${directory}/users/${staff}/tokens`, auth);
    expect(response.status).toBe(200);
    const body = (await response.json()) as { kind: string; etag: string; items: Record<string, unknown>[] };
    expect(body.kind).toBe("admin#directory#tokenList");
    expect(body.etag).toMatch(/^".+"$/);
    expect(body.items.map((token) => token.clientId).sort()).toEqual(["drive-client", "mail-client"]);
    const mail = body.items.find((token) => token.clientId === "mail-client")!;
    expect(mail).toMatchObject({
      kind: "admin#directory#token",
      clientId: "mail-client",
      displayText: "Mail reader",
      userKey: user.id,
      anonymous: false,
      nativeApp: false,
    });
    expect((mail.scopes as string[]).sort()).toEqual(["email", "https://mail.google.com/", "openid"]);
    expect(mail.etag).toMatch(/^".+"$/);

    const byId = (await (await request(`${directory}/users/${user.id}/tokens`, auth)).json()) as typeof body;
    expect(byId.items).toHaveLength(2);
  });

  it("lists no tokens for a user who granted none", async () => {
    const { request, adminToken } = fixture();
    const response = await request(`${directory}/users/${other}/tokens`, await adminToken());
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ kind: "admin#directory#tokenList", items: [] });
  });

  it("gets the token of one client", async () => {
    const { grant, request, adminToken } = fixture();
    await grant(staff, "drive", [scope("drive")]);
    const auth = await adminToken();
    const response = await request(`${directory}/users/${staff}/tokens/drive-client`, auth);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      kind: "admin#directory#token",
      clientId: "drive-client",
      displayText: "Drive backup",
      scopes: [scope("drive")],
    });
    const missing = await request(`${directory}/users/${staff}/tokens/mail-client`, auth);
    expect(missing.status).toBe(404);
    expect(await missing.json()).toMatchObject({ error: { code: 404, errors: [{ reason: "notFound" }] } });
  });

  it("deletes every access and refresh token the user holds for a client, and only those", async () => {
    const { grant, request, works, adminToken } = fixture();
    const first = await grant(staff, "mail", ["openid", "email"]);
    const second = await grant(staff, "mail", ["openid"]);
    const otherClient = await grant(staff, "drive", ["openid"]);
    const otherUser = await grant(other, "mail", ["openid"]);
    const auth = await adminToken();

    const response = await request(`${directory}/users/${staff}/tokens/mail-client`, auth, "DELETE");
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("");

    expect(await works(first, "mail")).toBe(false);
    expect(await works(second, "mail")).toBe(false);
    expect(await works(otherClient, "drive")).toBe(true);
    expect(await works(otherUser, "mail")).toBe(true);
    expect((await request(`${directory}/users/${staff}/tokens/mail-client`, auth)).status).toBe(404);
    const list = (await (await request(`${directory}/users/${staff}/tokens`, auth)).json()) as {
      items: { clientId: string }[];
    };
    expect(list.items.map((token) => token.clientId)).toEqual(["drive-client"]);
  });

  it("ends the caller's own access when an administrator deletes their own client's token", async () => {
    const { request, adminToken } = fixture();
    const auth = await adminToken();
    expect((await request(`${directory}/users/${admin}/tokens/admin-client`, auth, "DELETE")).status).toBe(200);
    expect((await request(`${directory}/users/${admin}/tokens`, auth)).status).toBe(401);
  });

  it("answers for unknown users as the other user methods do", async () => {
    const { request, adminToken } = fixture();
    const auth = await adminToken();
    for (const [path, method] of [
      [`${directory}/users/nobody@clinic.example/tokens`, "GET"],
      [`${directory}/users/nobody@clinic.example/tokens/mail-client`, "GET"],
      [`${directory}/users/nobody@clinic.example/tokens/mail-client`, "DELETE"],
    ]) {
      const response = await request(path, auth, method);
      expect(response.status, `${method} ${path}`).toBe(404);
      expect(await response.json()).toMatchObject({
        error: { message: "Resource Not Found: userKey", errors: [{ reason: "notFound" }] },
      });
    }
  });

  it("requires the user security scope and a super administrator", async () => {
    const { grant, request, adminToken } = fixture();
    const withoutScope = await adminToken([scope("admin.directory.user")]);
    for (const method of ["GET", "DELETE"]) {
      const response = await request(`${directory}/users/${staff}/tokens/mail-client`, withoutScope, method);
      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({ error: { errors: [{ reason: "insufficientPermissions" }] } });
    }
    const nonAdmin = (await grant(staff, "admin", [security])).access_token;
    const response = await request(`${directory}/users/${other}/tokens`, nonAdmin);
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: { errors: [{ reason: "forbidden" }] } });
  });

  it("describes the tokens resource in the discovery document", async () => {
    const { app } = fixture();
    const doc = (await (await app.request(`${base}/discovery/v1/apis/admin/directory_v1/rest`)).json()) as any;
    expect(Object.keys(doc.resources.tokens.methods).sort()).toEqual(["delete", "get", "list"]);
    expect(doc.resources.tokens.methods.delete).toMatchObject({
      httpMethod: "DELETE",
      path: "admin/directory/v1/users/{userKey}/tokens/{clientId}",
      scopes: [security],
    });
    expect(doc.schemas.Token.properties.clientId.type).toBe("string");
    expect(doc.schemas.Tokens.properties.items.items.$ref).toBe("Token");
    expect(doc.auth.oauth2.scopes[security]).toBeDefined();
  });
});
