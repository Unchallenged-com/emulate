import { createHash, randomBytes } from "node:crypto";
import { clientAddress, type Context, type Store } from "@emulators/core";
import { etagOf, findUserByKey, getCustomerId } from "./directory.js";
import type {
  GoogleActivity,
  GoogleActivityEvent,
  GoogleActivityParameter,
  GoogleActivityResource,
  GoogleUser,
} from "./entities.js";
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
  resources: GoogleActivityResource[] = [],
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
    events:
      resources.length > 0 ? events.map((event) => ({ ...event, resourceIds: resources.map((r) => r.id) })) : events,
    ...(resources.length > 0 ? { resource_details: resources } : {}),
  });
}

/**
 * The user a sign-in event concerns, as recent recorded `login` activities name it: in `resourceDetails`, `type`
 * `USER` with the user's address as `title` and the account (`customerIdentity`, the customer ID without its leading
 * `C`) as `CUSTOMER` owner, and its `id` in each event's `resourceIds` (raw and parser-normalized records of 2025 and
 * 2026; the Reports discovery document's `ResourceDetails` and `OwnerDetails`). Google does not document how that
 * `id` is made, a short lowercase identifier in the records; the emulator derives a stable one from the user's ID.
 */
function userResource(store: Store, user: GoogleUser): GoogleActivityResource {
  const digest = BigInt(`0x${createHash("sha256").update(`resource:${user.uid}`).digest("hex")}`);
  return {
    id: `0${digest.toString(32).slice(0, 13)}`,
    ownerDetails: {
      ownerIdentity: [{ customerIdentity: { id: getCustomerId(store).replace(/^C/, "") } }],
      ownerType: "CUSTOMER",
    },
    title: user.email,
    type: "USER",
  };
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
  record(c, store, "login", user, [{ type: "login", name, parameters }], null, [userResource(store, user)]);
}

/**
 * The `login_verification` ("A login verification was presented") that recorded activities pair with each SAML
 * sign-in, as a separate activity at the same time: `login_type` and `login_challenge_method` `saml`,
 * `login_challenge_status` `passed`, and `is_second_factor` without a value (a raw record of 2026-10; the reference
 * shows the status as "Challenge Passed." in the Admin console's wording).
 */
export function recordSamlVerification(c: Context, store: Store, user: GoogleUser | undefined): void {
  if (!inAccount(user)) return;
  record(
    c,
    store,
    "login",
    user,
    [
      {
        type: "login",
        name: "login_verification",
        parameters: [
          param("login_type", "saml"),
          { name: "login_challenge_method", multiValue: ["saml"] },
          param("login_challenge_status", "passed"),
          { name: "is_second_factor" },
        ],
      },
    ],
    null,
    [userResource(store, user)],
  );
}

/**
 * A `logout` ("A user logged out"). Its login type is Google Password whatever the sign-in was ("the Login type for
 * Logout events is displayed as Google Password", https://knowledge.workspace.google.com/admin/reports/user-log-events),
 * and recorded logouts carry no other parameter.
 */
export function recordLogout(c: Context, store: Store, user: GoogleUser | undefined): void {
  if (!inAccount(user)) return;
  record(
    c,
    store,
    "login",
    user,
    [{ type: "login", name: "logout", parameters: [param("login_type", "google_password")] }],
    null,
    [userResource(store, user)],
  );
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

/**
 * The product buckets of a scope in a token event's `scope_data`, among the values of the token events reference.
 * Google does not document which bucket a scope belongs to. Recorded activities give `GSUITE_ADMIN` for Admin SDK
 * scopes, `GMAIL` for Gmail scopes, `IDENTITY` for `openid` and `userinfo.profile`, and `IDENTITY` with `OTHER` for
 * `userinfo.email` (third-party parser test records of 2020 to 2024); Drive and Calendar scopes take the bucket named
 * after their product, as the API's own calls do in `activity` events. `email` and `profile` are the short forms of
 * the `userinfo` scopes. A scope no source places, such as the Groups Settings API's, is left out of `scope_data`.
 */
function productBuckets(scope: string): string[] | null {
  const name = scope.replace(/^https:\/\/www\.googleapis\.com\/auth\//, "");
  if (scope === "https://mail.google.com/" || name.startsWith("gmail.")) return ["GMAIL"];
  if (name === "drive" || name.startsWith("drive.")) return ["DRIVE"];
  if (name === "calendar" || name.startsWith("calendar.")) return ["CALENDAR"];
  if (name.startsWith("admin.")) return ["GSUITE_ADMIN"];
  if (name === "openid" || name === "profile" || name === "userinfo.profile") return ["IDENTITY"];
  if (name === "email" || name === "userinfo.email") return ["IDENTITY", "OTHER"];
  return null;
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
  const granted = scopes.length > 0 ? scopes : ["openid", "email", "profile"];
  const scopeData = granted.flatMap((scope) => {
    const buckets = productBuckets(scope);
    return buckets
      ? [{ parameter: [param("scope_name", scope), { name: "product_bucket", multiValue: buckets }] }]
      : [];
  });
  // The order of recorded activities: `scope_data` before `scope`.
  record(c, store, "token", user, [
    {
      type: "auth",
      name,
      parameters: [
        param("client_id", clientId),
        param("app_name", client?.name ?? clientId),
        param("client_type", clientType(client?.redirect_uris ?? [])),
        ...(scopeData.length > 0 ? [{ name: "scope_data", multiMessageValue: scopeData }] : []),
        { name: "scope", multiValue: granted },
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
    ...(activity.resource_details ? { resourceDetails: activity.resource_details } : {}),
  };
  return { ...resource, etag: etagOf(resource) };
}
