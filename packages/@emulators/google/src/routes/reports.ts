import type { Context, RouteContext } from "@emulators/core";
import {
  etagOf,
  findUserByKey,
  getCustomerId,
  parseFieldSelector,
  requireSuperAdmin,
  selectFields,
} from "../directory.js";
import type { GoogleActivity, GoogleActivityParameter } from "../entities.js";
import { googleApiError } from "../helpers.js";
import { activityResource } from "../reports.js";
import { buildReportsDiscoveryDocument } from "../reports-discovery.js";
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

  app.get("/discovery/v1/apis/admin/reports_v1/rest", (c) => c.json(buildReportsDiscoveryDocument(baseUrl)));

  // activities.list (https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list).
  app.get(`${PREFIX}/activity/users/:userKey/applications/:applicationName`, (c) => {
    const admin = requireSuperAdmin(c, store);
    if (admin instanceof Response) return admin;

    const application = c.req.param("applicationName") ?? "";
    if (!APPLICATIONS.has(application)) return invalid(c, `Invalid Input: applicationName`);
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

    const eventName = c.req.query("eventName");
    const conditions = parseFilters(c.req.query("filters") ?? "");
    const actorIp = c.req.query("actorIpAddress");
    // "Used to filter on the `oAuthClientId` field present in `ApplicationInfo` message", written
    // `applicationInfoFilter=oAuthClientId="clientId"`. Google does not document other forms; the emulator refuses them.
    const applicationFilter = c.req.query("applicationInfoFilter");
    const oauthClientId =
      applicationFilter === undefined ? undefined : /^oAuthClientId="([^"]*)"$/.exec(applicationFilter.trim())?.[1];
    if (applicationFilter !== undefined && oauthClientId === undefined) {
      return invalid(c, "Invalid Input: applicationInfoFilter");
    }

    const matching = gs.activities
      .findBy("application_name", application)
      .filter((activity) => {
        const time = Date.parse(activity.time);
        if (time < start || time > end) return false;
        if (user && activity.actor_profile_id !== user.uid) return false;
        if (actorIp && activity.ip_address !== actorIp) return false;
        if (oauthClientId !== undefined && activity.actor_oauth_client_id !== oauthClientId) return false;
        // "When retrieving by eventName, the API retrieves the activities where this event occurred. For each
        // activity, the response includes all of the activity's events including the event specified."
        const events = activity.events.filter((event) => !eventName || event.name === eventName);
        return events.some((event) => conditions.every((condition) => satisfies(event.parameters, condition)));
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
}
