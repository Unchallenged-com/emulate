import { describe, expect, it } from "vitest";
import { Hono, Store, WebhookDispatcher, authMiddleware, type AppEnv, type TokenMap } from "@emulators/core";
import { googlePlugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";
const drive = "https://www.googleapis.com/auth/drive";
const redirectUri = "http://localhost/callback";
const clients = {
  app: { client_id: "app-client", client_secret: "app-secret" },
  other: { client_id: "other-client", client_secret: "other-secret" },
};
const alice = "alice@example.com";
const bob = "bob@example.com";

type Client = keyof typeof clients;
type Grant = { access_token: string; refresh_token: string };

function fixture(strict?: boolean) {
  const app = new Hono<AppEnv>();
  const store = new Store();
  const tokens: TokenMap = new Map();
  const fallback = { login: alice, id: 1, scopes: [drive] };
  app.use("*", authMiddleware(tokens, undefined, fallback));
  googlePlugin.register(app, store, new WebhookDispatcher(), base, tokens);
  googlePlugin.seed?.(store, base);
  seedFromConfig(store, base, {
    ...(strict === undefined ? {} : { strict_scopes: strict }),
    users: [
      { email: alice, name: "Alice Example" },
      { email: bob, name: "Bob Example" },
    ],
    oauth_clients: Object.values(clients).map((client) => ({ ...client, redirect_uris: [redirectUri] })),
  });

  const form = (path: string, body: Record<string, string>) =>
    app.request(`${base}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body).toString(),
    });

  async function grant(email = alice, client: Client = "app"): Promise<Grant> {
    const { client_id } = clients[client];
    const authorize = await form("/o/oauth2/v2/auth/callback", {
      email,
      redirect_uri: redirectUri,
      scope: drive,
      client_id,
    });
    const code = new URL(authorize.headers.get("Location")!).searchParams.get("code")!;
    const exchange = await form("/oauth2/token", {
      ...clients[client],
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
    });
    expect(exchange.status).toBe(200);
    return (await exchange.json()) as Grant;
  }

  const refresh = (token: string, client: Client = "app") =>
    form("/oauth2/token", { ...clients[client], grant_type: "refresh_token", refresh_token: token });
  const revoke = (body: Record<string, string>) => form("/oauth2/revoke", body);
  const files = (token: string) =>
    app.request(`${base}/drive/v3/files`, { headers: { Authorization: `Bearer ${token}` } });

  async function works(issued: Grant, client: Client = "app"): Promise<boolean> {
    const access = (await files(issued.access_token)).status === 200;
    const refreshed = (await refresh(issued.refresh_token, client)).status === 200;
    expect(access, "access and refresh tokens agree").toBe(refreshed);
    return access;
  }

  return { grant, refresh, revoke, works };
}

describe("Google token revocation in strict mode", () => {
  it.each(["access_token", "refresh_token"] as const)(
    "revoking the %s of a grant ends every token the user holds for the client",
    async (credential) => {
      const { grant, revoke, works } = fixture(true);
      const revoked = await grant();
      const sameClient = await grant();
      const otherClient = await grant(alice, "other");
      const otherUser = await grant(bob);

      const response = await revoke({ token: revoked[credential] });
      expect(response.status).toBe(200);

      expect(await works(revoked)).toBe(false);
      expect(await works(sameClient)).toBe(false);
      expect(await works(otherClient, "other")).toBe(true);
      expect(await works(otherUser)).toBe(true);
    },
  );

  it("lets the user grant the client access again after a revocation", async () => {
    const { grant, revoke, works } = fixture(true);
    await revoke({ token: (await grant()).refresh_token });
    expect(await works(await grant())).toBe(true);
  });

  it("answers 400 invalid_token for unknown and already revoked tokens", async () => {
    const { grant, revoke } = fixture(true);
    const issued = await grant();
    expect((await revoke({ token: issued.access_token })).status).toBe(200);
    for (const token of ["unknown", issued.access_token, issued.refresh_token]) {
      const response = await revoke({ token });
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({ error: "invalid_token" });
    }
  });

  it("answers 400 invalid_request when no token is given", async () => {
    const { revoke } = fixture(true);
    for (const body of [{}, { token: "" }] as Record<string, string>[]) {
      const response = await revoke(body);
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({ error: "invalid_request", error_description: "Bad Request" });
    }
  });
});

describe.each([undefined, false])("Google token revocation in permissive mode (strict_scopes=%s)", (strict) => {
  it("revokes only the given refresh token and answers 200 for any token", async () => {
    const { grant, refresh, revoke } = fixture(strict);
    const revoked = await grant();
    const sameClient = await grant();
    expect((await revoke({ token: revoked.refresh_token })).status).toBe(200);
    expect((await refresh(revoked.refresh_token)).status).toBe(400);
    expect((await refresh(sameClient.refresh_token)).status).toBe(200);
    for (const body of [{ token: "unknown" }, { token: revoked.refresh_token }, {}] as Record<string, string>[]) {
      expect((await revoke(body)).status).toBe(200);
    }
  });
});
