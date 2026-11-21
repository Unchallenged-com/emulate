import { randomBytes } from "node:crypto";
import { clientAddress, type AppEnv, type Context, type Handler, type Hono, type Store } from "@emulators/core";
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

/** A sign-in event (`login_success`, `login_failure`) of the Login application, type `login`. */
export function recordLoginEvent(
  c: Context,
  store: Store,
  user: GoogleUser | undefined,
  name: "login_success" | "login_failure",
): void {
  if (!inAccount(user)) return;
  // The emulator's sign-in stands for a password sign-in: `google_password`, "The user provides a Google account
  // password", with the `password` challenge. It does not assess risk, so no sign-in is suspicious.
  const parameters: GoogleActivityParameter[] = [
    param("login_type", "google_password"),
    { name: "login_challenge_method", multiValue: ["password"] },
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

// The API methods the emulator serves, by route, with their IDs in Google's discovery documents. A recorded `activity`
// event names its method that way (`reports.activities.list`, of the API named `admin`).
const API_METHODS: Record<string, string> = {
  "GET /admin/directory/v1/users": "directory.users.list",
  "GET /admin/directory/v1/users/:userKey": "directory.users.get",
  "POST /admin/directory/v1/users": "directory.users.insert",
  "PUT /admin/directory/v1/users/:userKey": "directory.users.update",
  "PATCH /admin/directory/v1/users/:userKey": "directory.users.patch",
  "DELETE /admin/directory/v1/users/:userKey": "directory.users.delete",
  "POST /admin/directory/v1/users/:userKey/makeAdmin": "directory.users.makeAdmin",
  "POST /admin/directory/v1/users/:userKey/signOut": "directory.users.signOut",
  "GET /admin/directory/v1/users/:userKey/tokens": "directory.tokens.list",
  "GET /admin/directory/v1/users/:userKey/tokens/:clientId": "directory.tokens.get",
  "DELETE /admin/directory/v1/users/:userKey/tokens/:clientId": "directory.tokens.delete",
  "GET /admin/directory/v1/groups": "directory.groups.list",
  "GET /admin/directory/v1/groups/:groupKey": "directory.groups.get",
  "POST /admin/directory/v1/groups": "directory.groups.insert",
  "PUT /admin/directory/v1/groups/:groupKey": "directory.groups.update",
  "PATCH /admin/directory/v1/groups/:groupKey": "directory.groups.patch",
  "DELETE /admin/directory/v1/groups/:groupKey": "directory.groups.delete",
  "GET /admin/directory/v1/groups/:groupKey/members": "directory.members.list",
  "GET /admin/directory/v1/groups/:groupKey/members/:memberKey": "directory.members.get",
  "GET /admin/directory/v1/groups/:groupKey/hasMember/:memberKey": "directory.members.hasMember",
  "POST /admin/directory/v1/groups/:groupKey/members": "directory.members.insert",
  "PUT /admin/directory/v1/groups/:groupKey/members/:memberKey": "directory.members.update",
  "PATCH /admin/directory/v1/groups/:groupKey/members/:memberKey": "directory.members.patch",
  "DELETE /admin/directory/v1/groups/:groupKey/members/:memberKey": "directory.members.delete",
  "GET /admin/reports/v1/activity/users/:userKey/applications/:applicationName": "reports.activities.list",
  "GET /calendar/v3/users/:userId/calendarList": "calendar.calendarList.list",
  "GET /calendar/v3/calendars/:calendarId/events": "calendar.events.list",
  "POST /calendar/v3/calendars/:calendarId/events": "calendar.events.insert",
  "DELETE /calendar/v3/calendars/:calendarId/events/:eventId": "calendar.events.delete",
  "POST /calendar/v3/freeBusy": "calendar.freebusy.query",
  "GET /drive/v3/files": "drive.files.list",
  "POST /drive/v3/files": "drive.files.create",
  "POST /upload/drive/v3/files": "drive.files.create",
  "GET /drive/v3/files/:fileId": "drive.files.get",
  "PATCH /drive/v3/files/:fileId": "drive.files.update",
  "GET /gmail/v1/users/:userId/drafts": "gmail.users.drafts.list",
  "POST /gmail/v1/users/:userId/drafts": "gmail.users.drafts.create",
  "POST /upload/gmail/v1/users/:userId/drafts": "gmail.users.drafts.create",
  "GET /gmail/v1/users/:userId/drafts/:id": "gmail.users.drafts.get",
  "PUT /gmail/v1/users/:userId/drafts/:id": "gmail.users.drafts.update",
  "POST /gmail/v1/users/:userId/drafts/send": "gmail.users.drafts.send",
  "POST /upload/gmail/v1/users/:userId/drafts/send": "gmail.users.drafts.send",
  "DELETE /gmail/v1/users/:userId/drafts/:id": "gmail.users.drafts.delete",
  "GET /gmail/v1/users/:userId/history": "gmail.users.history.list",
  "POST /gmail/v1/users/:userId/watch": "gmail.users.watch",
  "POST /gmail/v1/users/:userId/stop": "gmail.users.stop",
  "GET /gmail/v1/users/:userId/labels": "gmail.users.labels.list",
  "GET /gmail/v1/users/:userId/labels/:id": "gmail.users.labels.get",
  "POST /gmail/v1/users/:userId/labels": "gmail.users.labels.create",
  "PUT /gmail/v1/users/:userId/labels/:id": "gmail.users.labels.update",
  "PATCH /gmail/v1/users/:userId/labels/:id": "gmail.users.labels.patch",
  "DELETE /gmail/v1/users/:userId/labels/:id": "gmail.users.labels.delete",
  "GET /gmail/v1/users/:userId/messages": "gmail.users.messages.list",
  "POST /gmail/v1/users/:userId/messages/batchModify": "gmail.users.messages.batchModify",
  "POST /gmail/v1/users/:userId/messages/batchDelete": "gmail.users.messages.batchDelete",
  "POST /gmail/v1/users/:userId/messages/import": "gmail.users.messages.import",
  "POST /upload/gmail/v1/users/:userId/messages/import": "gmail.users.messages.import",
  "POST /gmail/v1/users/:userId/messages/send": "gmail.users.messages.send",
  "POST /upload/gmail/v1/users/:userId/messages/send": "gmail.users.messages.send",
  "POST /gmail/v1/users/:userId/messages": "gmail.users.messages.insert",
  "POST /upload/gmail/v1/users/:userId/messages": "gmail.users.messages.insert",
  "GET /gmail/v1/users/:userId/messages/:messageId/attachments/:id": "gmail.users.messages.attachments.get",
  "GET /gmail/v1/users/:userId/messages/:id": "gmail.users.messages.get",
  "POST /gmail/v1/users/:userId/messages/:id/modify": "gmail.users.messages.modify",
  "POST /gmail/v1/users/:userId/messages/:id/trash": "gmail.users.messages.trash",
  "POST /gmail/v1/users/:userId/messages/:id/untrash": "gmail.users.messages.untrash",
  "DELETE /gmail/v1/users/:userId/messages/:id": "gmail.users.messages.delete",
  "GET /gmail/v1/users/:userId/settings/filters": "gmail.users.settings.filters.list",
  "POST /gmail/v1/users/:userId/settings/filters": "gmail.users.settings.filters.create",
  "DELETE /gmail/v1/users/:userId/settings/filters/:id": "gmail.users.settings.filters.delete",
  "GET /gmail/v1/users/:userId/settings/forwardingAddresses": "gmail.users.settings.forwardingAddresses.list",
  "GET /gmail/v1/users/:userId/settings/sendAs": "gmail.users.settings.sendAs.list",
  "GET /gmail/v1/users/:userId/threads": "gmail.users.threads.list",
  "GET /gmail/v1/users/:userId/threads/:id": "gmail.users.threads.get",
  "POST /gmail/v1/users/:userId/threads/:id/modify": "gmail.users.threads.modify",
  "POST /gmail/v1/users/:userId/threads/:id/trash": "gmail.users.threads.trash",
  "POST /gmail/v1/users/:userId/threads/:id/untrash": "gmail.users.threads.untrash",
  "DELETE /gmail/v1/users/:userId/threads/:id": "gmail.users.threads.delete",
};

// Each API by its discovery document's `name` (the Directory and Reports APIs are both `admin`), with its
// `product_bucket`, a value of the token events reference.
const API_PRODUCTS: Record<string, [api: string, product: string]> = {
  directory: ["admin", "GSUITE_ADMIN"],
  reports: ["admin", "GSUITE_ADMIN"],
  calendar: ["calendar", "CALENDAR"],
  drive: ["drive", "DRIVE"],
  gmail: ["gmail", "GMAIL"],
};

/**
 * An API call an application made with a user's token, as the OAuth Token application's `activity` event ("Access
 * activity for an application"), in the order of recorded activities. Only the calls the API answered, made with a
 * token the emulator issued from a grant, are recorded.
 */
function recordTokenActivity(c: Context, store: Store, methodId: string, responseBytes: number): void {
  const token = c.req.header("Authorization")?.match(/^Bearer\s+(\S+)\s*$/i)?.[1];
  const grant = token ? tokenGrant(store, token) : undefined;
  if (!grant) return;
  const gs = getGoogleStore(store);
  const user = gs.users.findOneBy("email", grant.email);
  if (!inAccount(user)) return;
  const client = gs.oauthClients.findOneBy("client_id", grant.clientId);
  const [api, product] = API_PRODUCTS[methodId.split(".")[0]];
  record(c, store, "token", user, [
    {
      type: "auth",
      name: "activity",
      parameters: [
        param("api_name", api),
        param("method_name", methodId),
        param("client_id", grant.clientId),
        { name: "num_response_bytes", intValue: String(responseBytes) },
        param("product_bucket", product),
        param("app_name", client?.name ?? grant.clientId),
        param("client_type", clientType(client?.redirect_uris ?? [])),
      ],
    },
  ]);
}

/**
 * The app the service's routes register on, recording each API call answered with success as a token `activity`
 * event. The routes it serves keep their handlers; only those of the methods above are wrapped.
 */
export function withTokenActivity(app: Hono<AppEnv>, store: Store): Hono<AppEnv> {
  const audited = Object.create(app) as Hono<AppEnv>;
  audited.on = (method: string, path: string, ...handlers: Handler<AppEnv>[]) => {
    const methodId = API_METHODS[`${method.toUpperCase()} ${path}`];
    const handler = handlers.pop();
    if (!methodId || !handler) {
      app.on(method, path, ...handlers, ...(handler ? [handler] : []));
      return audited;
    }
    const recorded: Handler<AppEnv> = async (c, next) => {
      const response = await handler(c, next);
      if (response instanceof Response && response.ok) {
        recordTokenActivity(c, store, methodId, (await response.clone().arrayBuffer()).byteLength);
      }
      return response;
    };
    app.on(method, path, ...handlers, recorded);
    return audited;
  };
  return audited;
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
