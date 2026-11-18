import { randomBytes } from "node:crypto";
import { clientAddress, type Context, type Store } from "@emulators/core";
import { etagOf, findUserByKey, getCustomerId } from "./directory.js";
import type { GoogleActivity, GoogleActivityEvent, GoogleActivityParameter, GoogleUser } from "./entities.js";
import { getAuthenticatedEmail } from "./helpers.js";
import { tokenGrant } from "./oauth-tokens.js";
import { getGoogleStore } from "./store.js";

// The audit records behind the Admin SDK Reports API's activities.list
// (https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list). Event types, names and
// parameters are Google's, from the activity events reference of each application:
// - login: https://developers.google.com/workspace/admin/reports/v1/appendix/activity/login
// - admin: https://developers.google.com/workspace/admin/reports/v1/appendix/activity/admin-user-settings and
//   https://developers.google.com/workspace/admin/reports/v1/appendix/activity/admin-group-settings
// - token: https://developers.google.com/workspace/admin/reports/v1/appendix/activity/token

export type ReportsApplication = GoogleActivity["application_name"];

export const param = (name: string, v: string): GoogleActivityParameter => ({ name, value: v });

/** A user of the account: activity reports cover the account's users only, those of a hosted domain. */
function inAccount(user: GoogleUser | undefined): user is GoogleUser {
  return Boolean(user?.hd && user.uid);
}

function record(
  c: Context,
  store: Store,
  application: ReportsApplication,
  actor: GoogleUser,
  events: GoogleActivityEvent[],
  oauthClientId: string | null = null,
): void {
  const gs = getGoogleStore(store);
  const client = oauthClientId ? gs.oauthClients.findOneBy("client_id", oauthClientId) : undefined;
  gs.activities.insert({
    application_name: application,
    time: new Date().toISOString(),
    // "Unique qualifier if multiple events have the same time", an int64.
    unique_qualifier: BigInt.asIntN(64, randomBytes(8).readBigUInt64BE()).toString(),
    actor_email: actor.email,
    actor_profile_id: actor.uid,
    actor_oauth_client_id: oauthClientId,
    actor_application_name: oauthClientId ? (client?.name ?? null) : null,
    ip_address: clientAddress(c.req.raw) ?? null,
    events,
  });
}

/**
 * A sign-in event (`login_success`, `login_failure`) of the Login application, type `login`. The emulator's sign-in
 * page stands for a password sign-in: `google_password`, "The user provides a Google account password", with the
 * `password` challenge. A sign-in through an SSO profile is `saml`, "The user provides a SAML assertion from a SAML
 * identity provider", the description Google gives both the login type and the challenge method.
 */
export function recordLoginEvent(
  c: Context,
  store: Store,
  user: GoogleUser | undefined,
  name: "login_success" | "login_failure",
  loginType: "google_password" | "saml" = "google_password",
): void {
  if (!inAccount(user)) return;
  // The emulator does not assess risk, so no sign-in is suspicious.
  const parameters: GoogleActivityParameter[] = [
    param("login_type", loginType),
    { name: "login_challenge_method", multiValue: [loginType === "saml" ? "saml" : "password"] },
  ];
  if (name === "login_success") parameters.push({ name: "is_suspicious", boolValue: false });
  // A suspended user is the documented `login_failure_account_disabled`: "The user's account is disabled."
  else parameters.push(param("login_failure_type", "login_failure_account_disabled"));
  record(c, store, "login", user, [{ type: "login", name, parameters }]);
}

// Desktop apps redirect to the loopback interface (https://developers.google.com/identity/protocols/oauth2/native-app),
// so a client whose redirect URIs are all there is `NATIVE_DESKTOP`, "A native Desktop application"; any other is `WEB`.
function clientType(redirectUris: string[]): string {
  const loopback = (uri: string) => {
    try {
      const url = new URL(uri);
      return url.protocol === "http:" && ["127.0.0.1", "[::1]", "localhost"].includes(url.hostname);
    } catch {
      return false;
    }
  };
  return redirectUris.length > 0 && redirectUris.every(loopback) ? "NATIVE_DESKTOP" : "WEB";
}

/** A grant (`authorize`) or its revocation (`revoke`) of the OAuth Token application, type `auth`. */
export function recordTokenEvent(
  c: Context,
  store: Store,
  email: string,
  name: "authorize" | "revoke",
  clientId: string,
  scope: string,
): void {
  const gs = getGoogleStore(store);
  const user = gs.users.findOneBy("email", email);
  if (!inAccount(user)) return;
  const client = gs.oauthClients.findOneBy("client_id", clientId);
  const scopes = scope.split(/\s+/).filter(Boolean);
  // The order of captured responses. They also carry `scope_data`, each scope with its product bucket; Google does not
  // document which bucket a scope belongs to, so the emulator leaves it out.
  record(c, store, "token", user, [
    {
      type: "auth",
      name,
      parameters: [
        param("client_id", clientId),
        param("app_name", client?.name ?? clientId),
        param("client_type", clientType(client?.redirect_uris ?? [])),
        { name: "scope", multiValue: scopes.length > 0 ? scopes : ["openid", "email", "profile"] },
      ],
    },
  ]);
}

/** The OAuth client of the access token a request carries, if the emulator issued it from a grant. */
function requestClientId(c: Context, store: Store): string | null {
  const token = c.get("authToken");
  return (token && tokenGrant(store, token)?.clientId) || null;
}

export const userEvent = (name: string, ...parameters: GoogleActivityParameter[]): GoogleActivityEvent => ({
  type: "USER_SETTINGS",
  name,
  parameters,
});

export const groupEvent = (name: string, ...parameters: GoogleActivityParameter[]): GoogleActivityEvent => ({
  type: "GROUP_SETTINGS",
  name,
  parameters,
});

/**
 * The changes one request of the calling administrator made through the Directory API, as one activity of the Admin
 * application (captured responses group the events of one change, such as a password and its next-login requirement).
 * The application the administrator called through is the actor's application, which Google fills "for third-party
 * apps" (https://knowledge.workspace.google.com/admin/reports/admin-log-events, "Actor application name").
 */
export function recordAdminActivity(c: Context, store: Store, events: GoogleActivityEvent[]): void {
  const email = getAuthenticatedEmail(c);
  const admin = email ? findUserByKey(getGoogleStore(store), email) : undefined;
  if (!inAccount(admin) || events.length === 0) return;
  record(c, store, "admin", admin, events, requestClientId(c, store));
}

/** An activity as the Reports API returns it. */
export function activityResource(store: Store, activity: GoogleActivity): Record<string, unknown> {
  const resource: Record<string, unknown> = {
    // The discovery document's defaults for `kind` (its descriptions name other values).
    kind: "admin#reports#activity",
    id: {
      time: activity.time,
      uniqueQualifier: activity.unique_qualifier,
      applicationName: activity.application_name,
      customerId: getCustomerId(store),
    },
    actor: {
      // Captured responses carry a caller type on Admin activities only.
      ...(activity.application_name === "admin" ? { callerType: "USER" } : {}),
      email: activity.actor_email,
      profileId: activity.actor_profile_id,
      ...(activity.actor_oauth_client_id
        ? {
            applicationInfo: {
              oauthClientId: activity.actor_oauth_client_id,
              ...(activity.actor_application_name ? { applicationName: activity.actor_application_name } : {}),
            },
          }
        : {}),
    },
    ...(activity.ip_address ? { ipAddress: activity.ip_address } : {}),
    events: activity.events,
  };
  return { ...resource, etag: etagOf(resource) };
}
