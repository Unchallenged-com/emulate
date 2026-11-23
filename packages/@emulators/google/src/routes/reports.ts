import type { Context, RouteContext } from "@emulators/core";
import {
  etagOf,
  findUserByKey,
  getCustomerId,
  parseFieldSelector,
  requireSuperAdmin,
  selectFields,
} from "../directory.js";
import type { GoogleActivity, GoogleActivityParameter, GoogleReportsChannel } from "../entities.js";
import { getAuthenticatedEmail, googleApiError } from "../helpers.js";
import { activityResource, requestClientId } from "../reports.js";
import { buildReportsDiscoveryDocument } from "../reports-discovery.js";
import {
  MAX_CHANNEL_LIFETIME_MS,
  channelResource,
  channelResourceId,
  sendSync,
  startChannelDelivery,
} from "../reports-push.js";
import { parseGoogleBody } from "../route-helpers.js";
import { getGoogleStore } from "../store.js";

const PREFIX = "/admin/reports/v1";

// The applications activities.list accepts, from the `applicationName` pattern of the discovery document. The emulator
// records `admin`, `login` and `token`; the others answer an empty report.
const APPLICATIONS = new Set([
  "access_evaluation",
  "access_transparency",
  "admin",
  "admin_data_action",
  "assignments",
  "calendar",
  "chat",
  "chrome",
  "chrome_sync",
  "classroom",
  "cloud_search",
  "contacts",
  "context_aware_access",
  "data_migration",
  "data_studio",
  "directory_sync",
  "drive",
  "gcp",
  "gemini_in_workspace_apps",
  "gemini_notebook",
  "gmail",
  "gplus",
  "graduation",
  "groups",
  "groups_enterprise",
  "jamboard",
  "keep",
  "ldap",
  "login",
  "meet",
  "meet_hardware",
  "mobile",
  "profile",
  "rules",
  "saml",
  "takeout",
  "tasks",
  "token",
  "user_accounts",
  "vault",
  "voice",
  "workspace_studio",
]);

// The applications activities.watch accepts, from its own `applicationName` pattern in the discovery document.
const WATCH_APPLICATIONS = new Set([
  "access_transparency",
  "admin",
  "calendar",
  "chat",
  "chrome",
  "classroom",
  "context_aware_access",
  "data_studio",
  "drive",
  "gcp",
  "gplus",
  "groups",
  "groups_enterprise",
  "jamboard",
  "keep",
  "login",
  "meet",
  "mobile",
  "rules",
  "saml",
  "token",
  "user_accounts",
]);

// The list parameters the emulator does not model: organizational units, group filtering, and the filters on fields
// its activities do not carry.
const UNSUPPORTED = [
  "orgUnitID",
  "groupIdFilter",
  "networkInfoFilter",
  "statusFilter",
  "deviceFilter",
  "resourceDetailsFilter",
  "agentInfoFilter",
  "includeSensitiveData",
];

// RFC 3339, the `startTime` and `endTime` pattern of the discovery document.
const RFC3339 = /^(\d\d\d\d)-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?(?:(Z)|([-+])(\d\d):(\d\d))$/;
// "If the `endTime` is not specified, the report returns all activities from the `startTime` until the current time
// or the most recent 180 days if the `startTime` is more than 180 days in the past."
const RETENTION_MS = 180 * 24 * 60 * 60 * 1000;

type Condition = { name: string; operator: string; value: string };

/**
 * `filters`: "a comma-separated list composed of event parameters manipulated by relational operators", with `==`,
 * `<>`, `<`, `<=`, `>` and `>=`. "If an invalid parameter is supplied in the API request, the API ignores that
 * parameter", so a condition without an operator is dropped.
 */
function parseFilters(filters: string): Condition[] {
  return filters
    .split(",")
    .map((part) => /^(.+?)(==|<>|<=|>=|<|>)(.*)$/.exec(part.trim()))
    .filter((match): match is RegExpExecArray => match !== null)
    .map(([, name, operator, value]) => ({ name: name.trim(), operator, value: value.trim() }));
}

function compare(actual: string, operator: string, expected: string): boolean {
  const numeric = /^-?\d+$/.test(actual) && /^-?\d+$/.test(expected);
  const order = numeric ? Math.sign(Number(actual) - Number(expected)) : actual.localeCompare(expected);
  switch (operator) {
    case "==":
      return order === 0;
    case "<>":
      return order !== 0;
    case "<":
      return order < 0;
    case "<=":
      return order <= 0;
    case ">":
      return order > 0;
    default:
      return order >= 0;
  }
}

function parameterValues(parameter: GoogleActivityParameter): string[] {
  if ("multiValue" in parameter) return parameter.multiValue;
  if ("boolValue" in parameter) return [String(parameter.boolValue)];
  return [parameter.value];
}

/** "An empty report is returned if the request's parameter doesn't belong to the `eventName`." */
function satisfies(parameters: GoogleActivityParameter[], condition: Condition): boolean {
  const parameter = parameters.find((p) => p.name === condition.name);
  if (!parameter) return false;
  const values = parameterValues(parameter);
  return condition.operator === "<>"
    ? values.every((v) => compare(v, "<>", condition.value))
    : values.some((v) => compare(v, condition.operator, condition.value));
}

/** What a list or watch request selects, beside its application and time range. */
type ActivityQuery = {
  userProfileId: string | null;
  eventName: string | null;
  conditions: Condition[];
  actorIp: string | null;
};

function matchesQuery(activity: GoogleActivity, query: ActivityQuery): boolean {
  if (query.userProfileId && activity.actor_profile_id !== query.userProfileId) return false;
  if (query.actorIp && activity.ip_address !== query.actorIp) return false;
  // "When retrieving by eventName, the API retrieves the activities where this event occurred. For each activity, the
  // response includes all of the activity's events including the event specified."
  const events = activity.events.filter((event) => !query.eventName || event.name === query.eventName);
  return events.some((event) => query.conditions.every((condition) => satisfies(event.parameters, condition)));
}

const channelQuery = (channel: GoogleReportsChannel): ActivityQuery => ({
  userProfileId: channel.user_profile_id,
  eventName: channel.event_name,
  conditions: parseFilters(channel.filters ?? ""),
  actorIp: channel.actor_ip_address,
});

// "This is your webhook callback URL, and it must use HTTPS." The emulator also accepts plain HTTP on the loopback
// interface, so local tests can receive notifications.
function acceptableAddress(value: string): boolean {
  if (!URL.canParse(value)) return false;
  const url = new URL(value);
  if (url.protocol === "https:") return true;
  return url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
}

// Google's answer to a watch request whose address is not HTTPS, as a real Drive files.watch answer shows it (Google
// documents no Reports-specific one; channels are shared by Google's push notifications).
function webhookUrlInvalid(c: Context): Response {
  const message = "Invalid webhook URL. Must be a valid URL starting with https";
  return c.json(
    { error: { errors: [{ domain: "push", reason: "push.webhookUrlInvalid", message }], code: 400, message } },
    400,
  );
}

// Page tokens hold the position of the last activity returned, so new activities do not shift the next page.
function pageToken(activity: GoogleActivity): string {
  return Buffer.from(`${activity.time}|${activity.id}`).toString("base64url");
}

function readPageToken(token: string): { time: string; id: number } | null {
  const [time, id] = Buffer.from(token, "base64url").toString().split("|");
  return time && Number.isInteger(Number(id)) ? { time, id: Number(id) } : null;
}

const newestFirst = (a: GoogleActivity, b: GoogleActivity) =>
  a.time === b.time ? b.id - a.id : a.time < b.time ? 1 : -1;

export function reportsRoutes({ app, store, baseUrl }: RouteContext): void {
  const gs = getGoogleStore(store);
  const badRequest = (c: Context, message: string) => googleApiError(c, 400, message, "badRequest", "INVALID_ARGUMENT");
  const invalid = (c: Context, message: string) => googleApiError(c, 400, message, "invalid", "INVALID_ARGUMENT");
  startChannelDelivery(store, (activity, channel) => matchesQuery(activity, channelQuery(channel)));

  /** The selection both list and watch read from their path and query, or the error that refuses it. */
  const readQuery = (c: Context, applications: Set<string>): (ActivityQuery & { userKey: string }) | Response => {
    const application = c.req.param("applicationName") ?? "";
    if (!applications.has(application)) return invalid(c, `Invalid Input: applicationName`);
    const unsupported = UNSUPPORTED.find((name) => c.req.query(name) !== undefined);
    if (unsupported) return badRequest(c, `Invalid Input: ${unsupported} is not supported by the emulator`);

    const customerId = c.req.query("customerId");
    if (customerId && customerId !== "my_customer" && customerId !== getCustomerId(store)) {
      return badRequest(c, "Bad Request");
    }

    // "`all` for all information, or `userKey` for a user's unique Google Workspace profile ID or their primary email
    // address. Must not be a deleted user." An unknown user answers `badRequest`.
    const userKey = c.req.param("userKey") ?? "";
    const user = userKey === "all" ? undefined : findUserByKey(gs, userKey);
    if (userKey !== "all" && !user) return badRequest(c, "Bad Request");

    return {
      userKey,
      userProfileId: user?.uid ?? null,
      eventName: c.req.query("eventName") || null,
      conditions: parseFilters(c.req.query("filters") ?? ""),
      actorIp: c.req.query("actorIpAddress") || null,
    };
  };

  app.get("/discovery/v1/apis/admin/reports_v1/rest", (c) => c.json(buildReportsDiscoveryDocument(baseUrl)));

  // activities.list (https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list).
  app.get(`${PREFIX}/activity/users/:userKey/applications/:applicationName`, (c) => {
    const admin = requireSuperAdmin(c, store);
    if (admin instanceof Response) return admin;
    const query = readQuery(c, APPLICATIONS);
    if (query instanceof Response) return query;

    // "The `startTime` must be before the `endTime` (if specified) and the current time when the request is made, or
    // the API returns an error."
    const now = Date.now();
    const startParam = c.req.query("startTime");
    const endParam = c.req.query("endTime");
    if (startParam !== undefined && !RFC3339.test(startParam)) return invalid(c, "Invalid Input: startTime");
    if (endParam !== undefined && !RFC3339.test(endParam)) return invalid(c, "Invalid Input: endTime");
    const end = endParam !== undefined ? Date.parse(endParam) : now;
    const start = startParam !== undefined ? Date.parse(startParam) : Math.max(0, end - RETENTION_MS);
    if (startParam !== undefined && (start > now || start > end)) return invalid(c, "Invalid Input: startTime");

    const requested = Number.parseInt(c.req.query("maxResults") ?? "", 10);
    const size = Number.isFinite(requested) && requested > 0 ? Math.min(requested, 1000) : 1000;
    const after = c.req.query("pageToken") ? readPageToken(c.req.query("pageToken")!) : null;
    if (c.req.query("pageToken") && !after) return invalid(c, "Invalid Input: pageToken");

    // "Used to filter on the `oAuthClientId` field present in `ApplicationInfo` message", written
    // `applicationInfoFilter=oAuthClientId="clientId"`, with the spaces around the operator that AIP-160 filters allow
    // (https://google.aip.dev/160). Other forms are "non-compliant", answered `INVALID_ARGUMENT`.
    const applicationFilter = c.req.query("applicationInfoFilter");
    const oauthClientId =
      applicationFilter === undefined
        ? undefined
        : /^oAuthClientId\s*=\s*"([^"]*)"$/.exec(applicationFilter.trim())?.[1];
    if (applicationFilter !== undefined && oauthClientId === undefined) {
      return invalid(c, "Invalid Input: applicationInfoFilter");
    }

    const matching = gs.activities
      .findBy("application_name", c.req.param("applicationName") ?? "")
      .filter((activity) => {
        const time = Date.parse(activity.time);
        if (time < start || time > end) return false;
        if (oauthClientId !== undefined && activity.actor_oauth_client_id !== oauthClientId) return false;
        return matchesQuery(activity, query);
      })
      .sort(newestFirst)
      .filter((activity) => !after || newestFirst(activity, { time: after.time, id: after.id } as GoogleActivity) > 0);

    const items = matching.slice(0, size);
    const resource = {
      kind: "admin#reports#activities",
      ...(items.length > 0 ? { items: items.map((activity) => activityResource(store, activity)) } : {}),
      ...(matching.length > size ? { nextPageToken: pageToken(items[items.length - 1]) } : {}),
    };
    const body = { ...resource, etag: etagOf(resource) };
    return c.json(selectFields(body, parseFieldSelector(c.req.query("fields") ?? "")));
  });

  // activities.watch (https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/watch): "You
  // can use the userKey, applicationName, eventName, and filters parameters to only receive notifications for
  // specific events, users, or applications."
  app.post(`${PREFIX}/activity/users/:userKey/applications/:applicationName/watch`, async (c) => {
    const admin = requireSuperAdmin(c, store);
    if (admin instanceof Response) return admin;
    const query = readQuery(c, WATCH_APPLICATIONS);
    if (query instanceof Response) return query;

    const body = await parseGoogleBody(c);
    const id = typeof body.id === "string" ? body.id : "";
    const address = typeof body.address === "string" ? body.address : "";
    // "With each watch request, you must provide these fields": `id`, `type` set to `web_hook`, and `address`. Google
    // does not document the answer to a missing one; the emulator answers `badRequest`.
    if (!id || body.type !== "web_hook" || !address) return badRequest(c, "Bad Request");
    if (!acceptableAddress(address)) return webhookUrlInvalid(c);

    // A channel's expiration is "determined either by your request or by any Admin SDK API internal limits or
    // defaults (the more restrictive value is used)".
    const now = Date.now();
    const requested = Number(body.expiration);
    const limit = now + MAX_CHANNEL_LIFETIME_MS;
    // An expiration already past is accepted, as Google does not document its answer: the channel sends only its sync.
    const expiration = body.expiration !== undefined && Number.isFinite(requested) ? Math.min(requested, limit) : limit;

    const application = c.req.param("applicationName") ?? "";
    // The guide's notification example: https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin?alt=json
    const resourceUri = `${baseUrl.replace(/\/$/, "")}${PREFIX}/activity/users/${encodeURIComponent(query.userKey)}/applications/${application}?alt=json`;
    // The `id` should be unique "within your project"; Google does not document the answer to a reused one, and the
    // emulator accepts it (channels.stop also matches the `resourceId`).
    const channel = gs.reportsChannels.insert({
      channel_id: id,
      resource_id: channelResourceId(resourceUri),
      resource_uri: resourceUri,
      address,
      token: typeof body.token === "string" ? body.token : null,
      expiration,
      application_name: application,
      user_profile_id: query.userProfileId,
      event_name: query.eventName,
      filters: c.req.query("filters") ?? null,
      actor_ip_address: query.actorIp,
      creator_email: getAuthenticatedEmail(c) ?? admin.email,
      creator_client_id: requestClientId(c, store),
      message_number: 1,
    });
    sendSync(channel);
    return c.json(channelResource(channel));
  });

  // channels.stop (https://developers.google.com/workspace/admin/reports/reference/rest/v1/channels/stop): "If the
  // channel was created by a regular user account, only the same user from the same client (as identified by the
  // OAuth 2.0 client IDs from the auth tokens) who created the channel can stop the channel." The path is the discovery
  // document's and the push guide's.
  app.post("/admin/reports_v1/channels/stop", async (c) => {
    const admin = requireSuperAdmin(c, store);
    if (admin instanceof Response) return admin;
    const body = await parseGoogleBody(c);
    const email = getAuthenticatedEmail(c) ?? admin.email;
    const clientId = requestClientId(c, store);
    const channel = gs.reportsChannels
      .findBy("channel_id", typeof body.id === "string" ? body.id : "")
      .find(
        (candidate) =>
          candidate.resource_id === body.resourceId &&
          candidate.creator_email === email &&
          candidate.creator_client_id === clientId,
      );
    // Google does not document the answer to an unknown channel; the emulator answers `notFound`.
    if (!channel) return googleApiError(c, 404, "Channel not found", "notFound", "NOT_FOUND");
    gs.reportsChannels.delete(channel.id);
    // "If successful, this method returns an empty response body."
    return c.body(null, 200);
  });
}
