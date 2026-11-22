import { describe, expect, it } from "vitest";
import { Hono, Store, WebhookDispatcher, authMiddleware } from "@emulators/core";
import type { TokenMap } from "@emulators/core";
import { totpCode } from "../credentials.js";
import { oktaPlugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";
const admin = { Authorization: "SSWS admin-token", "Content-Type": "application/json" };
const SECRET = "JBTWGV22G4ZGKV3N";

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
      { okta_id: "00u_bob", login: "bob@example.com", first_name: "Bob", last_name: "Roe", password: "Old-pass-1" },
      { okta_id: "00u_eve", login: "eve@example.com", status: "LOCKED_OUT" },
    ],
    factors: [{ user_okta_id: "00u_bob", provider: "GOOGLE", shared_secret: SECRET, okta_id: "ost_bob_google" }],
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

function signIn(app: Hono<any>, userRef: string) {
  return app.request(`${base}/oauth2/v1/authorize/callback`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ user_ref: userRef, redirect_uri: "http://localhost:3000/callback" }),
  });
}

describe("Okta factors", () => {
  it("enrolls a TOTP factor pending activation and activates it with a valid code", async () => {
    const app = createTestApp();
    const enrolled = await call(app, "POST", "/api/v1/users/00u_ada/factors", {
      factorType: "token:software:totp",
      provider: "OKTA",
    });
    expect(enrolled.status).toBe(200);
    expect(enrolled.body).toMatchObject({
      factorType: "token:software:totp",
      provider: "OKTA",
      vendorName: "OKTA",
      status: "PENDING_ACTIVATION",
      profile: { credentialId: "ada@example.com" },
      _embedded: { activation: { timeStep: 30, encoding: "base32", keyLength: 16 } },
    });
    const { id, _embedded } = enrolled.body;
    expect(_embedded.activation.sharedSecret).toMatch(/^[A-Z2-7]{16}$/);

    const wrong = await call(app, "POST", `/api/v1/users/00u_ada/factors/${id}/lifecycle/activate`, {
      passCode: "000000" === totpCode(_embedded.activation.sharedSecret) ? "111111" : "000000",
    });
    expect(wrong.status).toBe(403);
    expect(wrong.body).toMatchObject({ errorCode: "E0000068", errorSummary: "Invalid Passcode/Answer" });

    const activated = await call(app, "POST", `/api/v1/users/00u_ada/factors/${id}/lifecycle/activate`, {
      passCode: totpCode(_embedded.activation.sharedSecret),
    });
    expect(activated.status).toBe(200);
    expect(activated.body.status).toBe("ACTIVE");
    expect((await call(app, "GET", "/api/v1/users/00u_ada/factors")).body.map((f: any) => f.status)).toEqual([
      "ACTIVE",
    ]);

    const [event] = await events(app, "user.mfa.factor");
    expect(event).toMatchObject({
      eventType: "user.mfa.factor.activate",
      displayMessage: "Activate factor for user",
      legacyEventType: "core.user.factor.activate",
      outcome: { result: "SUCCESS", reason: "User set up OKTA_SOFT_TOKEN factor" },
      actor: { id: "00u_ada" },
      target: [{ id: "00u_ada", type: "User", alternateId: "ada@example.com" }],
    });
  });

  it("refuses an unsupported or duplicate factor", async () => {
    const app = createTestApp();
    const sms = await call(app, "POST", "/api/v1/users/00u_ada/factors", { factorType: "sms", provider: "OKTA" });
    expect(sms.status).toBe(400);
    expect(sms.body.errorCode).toBe("E0000001");
    const duplicate = await call(app, "POST", "/api/v1/users/00u_bob/factors", {
      factorType: "token:software:totp",
      provider: "GOOGLE",
    });
    expect(duplicate.status).toBe(400);
    expect(duplicate.body).toMatchObject({
      errorCode: "E0000001",
      errorSummary: "Api validation failed: factorEnrollRequest",
      errorCauses: [{ errorSummary: "A factor of this type is already set up." }],
    });
  });

  it("unenrolls a factor and resets all of them, with their events", async () => {
    const app = createTestApp();
    expect((await call(app, "GET", "/api/v1/users/00u_bob/factors/ost_bob_google")).body.status).toBe("ACTIVE");
    expect((await call(app, "DELETE", "/api/v1/users/00u_bob/factors/ost_bob_google")).status).toBe(204);
    expect((await call(app, "GET", "/api/v1/users/00u_bob/factors/ost_bob_google")).status).toBe(404);

    await call(app, "POST", "/api/v1/users/00u_bob/factors", { factorType: "token:software:totp", provider: "OKTA" });
    const reset = await call(app, "POST", "/api/v1/users/00u_bob/lifecycle/reset_factors");
    expect(reset.status).toBe(200);
    expect((await call(app, "GET", "/api/v1/users/00u_bob/factors")).body).toEqual([]);

    const recorded = await events(app, "user.mfa.factor");
    expect(recorded.map((event) => [event.eventType, event.outcome.reason])).toEqual([
      ["user.mfa.factor.deactivate", "User reset SOFT_TOKEN factor"],
      ["user.mfa.factor.deactivate", "User reset OKTA_SOFT_TOKEN factor"],
    ]);
    expect(recorded[0]).toMatchObject({ displayMessage: "Reset factor for user", target: [{ id: "00u_bob" }] });
  });
});

describe("Okta password lifecycle", () => {
  it("changes a password after checking the old one", async () => {
    const app = createTestApp();
    const wrong = await call(app, "POST", "/api/v1/users/00u_bob/credentials/change_password", {
      oldPassword: { value: "not-it" },
      newPassword: { value: "New-pass-2" },
    });
    expect(wrong.status).toBe(403);
    expect(wrong.body).toMatchObject({
      errorCode: "E0000014",
      errorSummary: "Update of credentials failed",
      errorCauses: [{ errorSummary: "oldPassword: The credentials provided were incorrect." }],
    });

    const changed = await call(app, "POST", "/api/v1/users/00u_bob/credentials/change_password", {
      oldPassword: { value: "Old-pass-1" },
      newPassword: { value: "New-pass-2" },
    });
    expect(changed.status).toBe(200);
    expect(changed.body).toEqual({ password: {}, provider: { type: "OKTA", name: "OKTA" } });
    const again = await call(app, "POST", "/api/v1/users/00u_bob/credentials/change_password", {
      oldPassword: { value: "New-pass-2" },
      newPassword: { value: "Third-pass-3" },
    });
    expect(again.status).toBe(200);

    const recorded = await events(app, "user.account.update_password");
    expect(recorded).toHaveLength(2);
    expect(recorded[0]).toMatchObject({
      displayMessage: "User update password for Okta",
      legacyEventType: "core.user.config.password_update.success",
      target: [{ id: "00u_bob", type: "User" }],
    });
  });

  it("resets a password into RECOVERY, and the user signs in again after changing it", async () => {
    const app = createTestApp();
    const reset = await call(app, "POST", "/api/v1/users/00u_bob/lifecycle/reset_password?sendEmail=false");
    expect(reset.status).toBe(200);
    expect(reset.body.resetPasswordUrl).toMatch(new RegExp(`^${base}/reset_password/`));
    expect((await call(app, "GET", "/api/v1/users/00u_bob")).body.status).toBe("RECOVERY");
    expect((await signIn(app, "00u_bob")).status).toBe(400);

    await call(app, "POST", "/api/v1/users/00u_bob/credentials/change_password", {
      oldPassword: { value: "Old-pass-1" },
      newPassword: { value: "New-pass-2" },
    });
    expect((await call(app, "GET", "/api/v1/users/00u_bob")).body.status).toBe("ACTIVE");
    expect((await signIn(app, "00u_bob")).status).toBe(302);

    const [event] = await events(app, "user.account.reset_password");
    expect(event).toMatchObject({
      legacyEventType: "core.user.config.user_status.password_reset",
      actor: { id: "00u_ada" },
      target: [{ id: "00u_bob" }],
    });
  });

  it("expires a password and unlocks a locked out user", async () => {
    const app = createTestApp();
    const expired = await call(app, "POST", "/api/v1/users/00u_bob/lifecycle/expire_password");
    expect(expired.status).toBe(200);
    expect(expired.body).toMatchObject({ id: "00u_bob", status: "PASSWORD_EXPIRED" });

    const notLocked = await call(app, "POST", "/api/v1/users/00u_bob/lifecycle/unlock");
    expect(notLocked.status).toBe(403);
    expect(notLocked.body).toMatchObject({
      errorCode: "E0000032",
      errorCauses: [{ errorSummary: "The user is not locked out." }],
    });
    expect((await call(app, "POST", "/api/v1/users/00u_eve/lifecycle/unlock")).status).toBe(200);
    expect((await call(app, "GET", "/api/v1/users/00u_eve")).body.status).toBe("ACTIVE");

    const recorded = await events(app, "user.account");
    expect(recorded.map((event) => event.eventType)).toEqual([
      "user.account.expire_password",
      "user.account.unlock_by_admin",
    ]);
  });

  it("refuses to reset or expire the password of a staged or suspended user, and answers {} when emailing", async () => {
    const app = createTestApp();
    const created = await call(app, "POST", "/api/v1/users?activate=false", {
      profile: { login: "stan@example.com", email: "stan@example.com" },
    });
    for (const path of ["reset_password", "expire_password"]) {
      const refused = await call(app, "POST", `/api/v1/users/${created.body.id}/lifecycle/${path}`);
      expect(refused.status).toBe(403);
      expect(refused.body).toMatchObject({ errorCode: "E0000017", errorSummary: "Password reset failed" });
    }
    const emailed = await call(app, "POST", "/api/v1/users/00u_bob/lifecycle/reset_password");
    expect(emailed.status).toBe(200);
    expect(emailed.body).toEqual({});
  });

  it("creates a user with a password", async () => {
    const app = createTestApp();
    const created = await call(app, "POST", "/api/v1/users", {
      profile: { login: "carol@example.com", email: "carol@example.com" },
      credentials: { password: { value: "Carol-pass-1" } },
    });
    expect(created.body.passwordChanged).not.toBeNull();
    const [update] = await events(app, "user.account.update_password");
    expect(update).toMatchObject({ actor: { id: "00u_ada" }, target: [{ id: created.body.id }] });
    const changed = await call(app, "POST", `/api/v1/users/${created.body.id}/credentials/change_password`, {
      oldPassword: { value: "Carol-pass-1" },
      newPassword: { value: "Carol-pass-2" },
    });
    expect(changed.status).toBe(200);
  });
});
