import { randomBytes } from "node:crypto";
import { clientAddress, type Context, type Store } from "@emulators/core";
import { etagOf, findUserByKey, getCustomerId } from "./directory.js";
import type {
  GoogleActivity,
  GoogleActivityEvent,
  GoogleActivityParameter,
  GoogleMessage,
  GoogleUser,
} from "./entities.js";
import { estimateSize, getAuthenticatedEmail } from "./helpers.js";
import { tokenGrant } from "./oauth-tokens.js";
import { getGoogleStore } from "./store.js";

// The audit records behind the Admin SDK Reports API's activities.list
// (https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list). Event types, names and
// parameters are Google's, from the activity events reference of each application:
// - login: https://developers.google.com/workspace/admin/reports/v1/appendix/activity/login
// - admin: https://developers.google.com/workspace/admin/reports/v1/appendix/activity/admin-user-settings and
//   https://developers.google.com/workspace/admin/reports/v1/appendix/activity/admin-group-settings
// - token: https://developers.google.com/workspace/admin/reports/v1/appendix/activity/token
// - gmail: https://developers.google.com/workspace/admin/reports/v1/appendix/activity/gmail

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

/** The Gmail log's `mail_event_type` values the emulator records, from the Gmail events reference. */
export const MailEvent = {
  sent: 1,
  markedUnread: 8,
  movedToInbox: 12,
  movedToTrash: 13,
  removedFromTrash: 14,
  attachmentDownloaded: 17,
  archived: 26,
  deleted: 27,
  accessedByApplication: 33,
} as const;

const nested = (name: string, parameter: GoogleActivityParameter[]): GoogleActivityParameter => ({
  name,
  messageValue: { parameter },
});
const int = (name: string, n: number): GoogleActivityParameter => ({ name, intValue: String(n) });

// "Name <address>" or a bare address, as RFC 5322 header values carry them.
function mailbox(value: string): { address: string; displayName?: string } {
  const match = /^\s*"?([^"<]*?)"?\s*<([^>]+)>\s*$/.exec(value);
  if (match) return { address: match[2].trim(), ...(match[1].trim() ? { displayName: match[1].trim() } : {}) };
  return { address: value.trim() };
}

const mailboxes = (header: string | null) =>
  (header ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map(mailbox);

/**
 * A Gmail log event (`delivery`, type `delivery_type`) of the mailbox's owner. Field names are those of Google's
 * Gmail log schema (https://knowledge.workspace.google.com/admin/reports/schema-for-gmail-logs-in-bigquery);
 * Reports API records nest them as `messageValue` parameters, and recorded activities carry `callerType` `USER`
 * (third-party parser test records). Only what the emulator knows is filled: no connection, spam or policy
 * information, `action_type`, `message_set`, or the destinations' `service` and `selector`.
 */
export function recordGmailEvent(c: Context, store: Store, message: GoogleMessage, mailEventType: number): void {
  const user = getGoogleStore(store).users.findOneBy("email", message.user_email);
  if (!inAccount(user)) return;
  const from = mailbox(message.from);
  const destinations = [...mailboxes(message.to), ...mailboxes(message.cc), ...mailboxes(message.bcc)];
  const attachments = getGoogleStore(store)
    .attachments.findBy("message_gmail_id", message.gmail_id)
    .filter((attachment) => attachment.user_email === message.user_email);
  const eventInfo = [
    int("mail_event_type", mailEventType),
    int("timestamp_usec", Date.now() * 1000),
    { name: "success", boolValue: true },
    // "Client or device type": the emulator serves the Gmail API only.
    nested("client_context", [param("client_type", "API")]),
  ];
  const messageInfo = [
    param("rfc2822_message_id", message.message_id),
    param("subject", message.subject),
    nested("source", [
      param("address", from.address),
      param("from_header_address", from.address),
      ...(from.displayName ? [param("from_header_displayname", from.displayName)] : []),
    ]),
    ...(destinations.length > 0
      ? [
          {
            name: "destination",
            multiMessageValue: destinations.map(({ address }) => ({ parameter: [param("address", address)] })),
          },
        ]
      : []),
    int("payload_size", estimateSize(message)),
    int("num_message_attachments", attachments.length),
  ];
  record(c, store, "gmail", user, [
    {
      type: "delivery_type",
      name: "delivery",
      parameters: [nested("event_info", eventInfo), nested("message_info", messageInfo)],
    },
  ]);
}

/** The Gmail log events of a label change: moved to Inbox, archived, or marked unread. */
export function recordGmailLabelEvents(c: Context, store: Store, before: string[], message: GoogleMessage): void {
  const added = (label: string) => !before.includes(label) && message.label_ids.includes(label);
  if (added("INBOX")) recordGmailEvent(c, store, message, MailEvent.movedToInbox);
  if (added("UNREAD")) recordGmailEvent(c, store, message, MailEvent.markedUnread);
  if (before.includes("INBOX") && !message.label_ids.includes("INBOX") && !message.label_ids.includes("TRASH")) {
    recordGmailEvent(c, store, message, MailEvent.archived);
  }
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
      // Captured responses carry a caller type on Admin activities; third-party parser test records, on Gmail ones too.
      ...(activity.application_name === "admin" || activity.application_name === "gmail" ? { callerType: "USER" } : {}),
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
