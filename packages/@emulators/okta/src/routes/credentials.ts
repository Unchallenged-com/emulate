import { randomBytes } from "node:crypto";
import type { RouteContext } from "@emulators/core";
import { hashPassword, verifyPassword } from "../credentials.js";
import type { OktaUser, OktaUserStatus } from "../entities.js";
import { boolFromQuery, nowIso } from "../helpers.js";
import { findUserByRef, oktaError, readJsonObject, requireManagementAuth, userResponse } from "../route-helpers.js";
import { getOktaStore } from "../store.js";
import { recordManagementEvent, userEntity } from "../system-log.js";
import { revokeUserOAuthTokens } from "./oauth.js";

// Password lifecycle operations of the Users API:
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserLifecycle/ and
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserCred/

// Okta answers E0000017 when it cannot reset or expire a password, for example for a STAGED or SUSPENDED user.
const PASSWORD_RESET_FAILED = "Password reset failed";
const RESET_REFUSED = new Set<OktaUserStatus>(["STAGED", "SUSPENDED", "DEPROVISIONED"]);

// "You can only perform this operation on users in STAGED, ACTIVE, PASSWORD_EXPIRED, or RECOVERY status."
const CHANGE_PASSWORD_STATUSES = new Set<OktaUserStatus>(["STAGED", "ACTIVE", "PASSWORD_EXPIRED", "RECOVERY"]);

function credentialsResponse(): Record<string, unknown> {
  return { password: {}, provider: { type: "OKTA", name: "OKTA" } };
}

export function credentialRoutes({ app, store, baseUrl, tokenMap }: RouteContext): void {
  const oktaStore = getOktaStore(store);

  const setStatus = (user: OktaUser, status: OktaUserStatus): OktaUser =>
    oktaStore.users.update(user.id, { status, status_changed_at: nowIso(), transitioning_to_status: null }) ?? user;

  app.post("/api/v1/users/:userId/lifecycle/reset_password", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");
    if (RESET_REFUSED.has(user.status)) return oktaError(c, 403, "E0000017", PASSWORD_RESET_FAILED);

    // "This operation transitions the user to the RECOVERY status"; a PROVISIONED user, who has not set a password
    // yet, stays PROVISIONED.
    const updated = user.status === "PROVISIONED" ? user : setStatus(user, "RECOVERY");
    if (boolFromQuery(c.req.query("revokeSessions"), false)) revokeUserOAuthTokens(store, user.okta_id, tokenMap);
    recordManagementEvent(store, c, auth, "user.account.reset_password", [userEntity(updated)]);

    // sendEmail defaults to true, and the answer is then an empty object; the emulator sends no email.
    if (!boolFromQuery(c.req.query("sendEmail"), true)) {
      const token = randomBytes(15).toString("base64url");
      return c.json({ resetPasswordUrl: `${baseUrl}/reset_password/${token}` });
    }
    return c.json({});
  });

  app.post("/api/v1/users/:userId/lifecycle/expire_password", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");
    if (RESET_REFUSED.has(user.status)) return oktaError(c, 403, "E0000017", PASSWORD_RESET_FAILED);
    // "This operation transitions the user status to PASSWORD_EXPIRED."
    const updated = setStatus(user, "PASSWORD_EXPIRED");
    recordManagementEvent(store, c, auth, "user.account.expire_password", [userEntity(updated)]);
    return c.json({ ...userResponse(baseUrl, updated), credentials: credentialsResponse() });
  });

  app.post("/api/v1/users/:userId/lifecycle/unlock", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");
    // "Unlocks a user with a LOCKED_OUT status"; the emulator has no blocking of unknown devices.
    if (user.status !== "LOCKED_OUT") {
      return oktaError(c, 403, "E0000032", "Unlock is not allowed for this user.", [
        { errorSummary: "The user is not locked out." },
      ]);
    }
    const updated = setStatus(user, "ACTIVE");
    recordManagementEvent(store, c, auth, "user.account.unlock_by_admin", [userEntity(updated)]);
    return c.body(null, 200);
  });

  app.post("/api/v1/users/:userId/credentials/change_password", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");
    if (!CHANGE_PASSWORD_STATUSES.has(user.status)) {
      return oktaError(c, 403, "E0000035", "Change password not allowed on specified user.");
    }

    const body = await readJsonObject(c);
    const oldPassword = (body.oldPassword as { value?: unknown } | undefined)?.value;
    const newPassword = (body.newPassword as { value?: unknown } | undefined)?.value;
    if (typeof newPassword !== "string" || newPassword === "") {
      return oktaError(c, 400, "E0000001", "Api validation failed: newPassword", [
        { errorSummary: "newPassword: The field cannot be left blank" },
      ]);
    }
    if (typeof oldPassword !== "string" || !verifyPassword(oldPassword, user.password_hash)) {
      return oktaError(c, 403, "E0000014", "Update of credentials failed", [
        { errorSummary: "oldPassword: The credentials provided were incorrect." },
      ]);
    }

    // "The user transitions to ACTIVE status when successfully invoked in RECOVERY status", and an expired password
    // is one "the user must change ... the next time that they sign in": changing it ends PASSWORD_EXPIRED too.
    const status: OktaUserStatus =
      user.status === "RECOVERY" || user.status === "PASSWORD_EXPIRED" ? "ACTIVE" : user.status;
    const now = nowIso();
    oktaStore.users.update(user.id, {
      password_hash: hashPassword(newPassword),
      password_changed_at: now,
      status,
      status_changed_at: status === user.status ? user.status_changed_at : now,
    });
    if (body.revokeSessions === true) revokeUserOAuthTokens(store, user.okta_id, tokenMap);
    recordManagementEvent(store, c, auth, "user.account.update_password", [userEntity(user)]);
    return c.json(credentialsResponse());
  });
}
