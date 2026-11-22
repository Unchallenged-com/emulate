import { randomUUID } from "node:crypto";
import type { Context, RouteContext } from "@emulators/core";
import {
  type GoogleAlert,
  alertCustomerId,
  alertMetadataResource,
  alertResource,
  getAlert,
  listAlerts,
} from "../alert-center.js";
import { requireSuperAdmin } from "../directory.js";
import { getAuthenticatedEmail, googleApiError } from "../helpers.js";
import { parseGoogleBody } from "../route-helpers.js";

const PREFIX = "/v1beta1";
// "This alert is removed from Alert Center after 30 days" once marked for deletion.
const DELETION_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const FEEDBACK_TYPES = new Set(["NOT_USEFUL", "SOMEWHAT_USEFUL", "VERY_USEFUL"]);

type Condition = { field: string; operator: string; value: string };

/**
 * The query filter of alerts.list (https://developers.google.com/workspace/admin/alertcenter/guides/query-filters):
 * conditions on `alertId`, `type`, `source`, `createTime`, `startTime` and `endTime`
 * (https://developers.google.com/workspace/admin/alertcenter/reference/filter-fields#alerts.list), joined with `AND`.
 */
function parseFilter(filter: string): Condition[] | null {
  const parts = filter.trim() ? filter.split(/\s+AND\s+/) : [];
  const conditions: Condition[] = [];
  for (const part of parts) {
    const match = /^\s*(alertId|type|source|createTime|startTime|endTime)\s*(>=|<=|!=|=|:|<|>)\s*"?([^"]*)"?\s*$/.exec(
      part,
    );
    if (!match) return null;
    conditions.push({ field: match[1], operator: match[2], value: match[3] });
  }
  return conditions;
}

function matches(alert: GoogleAlert, condition: Condition): boolean {
  const actual = (alert as unknown as Record<string, string | undefined>)[condition.field];
  if (actual === undefined) return false;
  if (condition.field.endsWith("Time")) {
    const order = Math.sign(Date.parse(actual) - Date.parse(condition.value));
    return {
      ">=": order >= 0,
      "<=": order <= 0,
      ">": order > 0,
      "<": order < 0,
      "=": order === 0,
      ":": order === 0,
      "!=": order !== 0,
    }[condition.operator]!;
  }
  if (condition.operator === "!=") return actual !== condition.value;
  return actual === condition.value;
}

const ORDERS: Record<string, (a: GoogleAlert, b: GoogleAlert) => number> = {
  "create_time asc": (a, b) => a.createTime.localeCompare(b.createTime),
  "create_time desc": (a, b) => b.createTime.localeCompare(a.createTime),
  "update_time desc": (a, b) => b.updateTime.localeCompare(a.updateTime),
};

export function alertCenterRoutes({ app, store }: RouteContext): void {
  const notFound = (c: Context) => googleApiError(c, 404, "Requested entity was not found.", "notFound", "NOT_FOUND");
  const invalid = (c: Context, message: string) => googleApiError(c, 400, message, "badRequest", "INVALID_ARGUMENT");

  /** A super administrator of the account, and a `customerId` that names it when one is given. */
  const authorize = (c: Context, customerId?: string): Response | null => {
    const admin = requireSuperAdmin(c, store);
    if (admin instanceof Response) return admin;
    if (customerId && customerId !== alertCustomerId(store)) return invalid(c, "Invalid customer ID");
    return null;
  };

  const live = (alertId: string): GoogleAlert | undefined => {
    const alert = getAlert(store, alertId);
    if (!alert) return undefined;
    if (alert.deleted && Date.now() - Date.parse(alert.updateTime) > DELETION_RETENTION_MS) return undefined;
    return alert;
  };

  // alerts.list. Chosen: alerts marked for deletion are left out of the list, and a list without `pageSize` returns
  // every alert (the server "picks an appropriate default").
  app.get(`${PREFIX}/alerts`, (c) => {
    const refused = authorize(c, c.req.query("customerId"));
    if (refused) return refused;
    const conditions = parseFilter(c.req.query("filter") ?? "");
    if (!conditions) return invalid(c, "Invalid filter");
    const orderBy = c.req.query("orderBy");
    if (orderBy && !ORDERS[orderBy]) return invalid(c, "Invalid orderBy");
    const size = Number.parseInt(c.req.query("pageSize") ?? "", 10);
    const offset = Number.parseInt(Buffer.from(c.req.query("pageToken") ?? "", "base64url").toString() || "0", 10);
    if (!Number.isInteger(offset) || offset < 0) return invalid(c, "Invalid pageToken");

    const matching = listAlerts(store)
      .filter((alert) => !alert.deleted && conditions.every((condition) => matches(alert, condition)))
      .sort(ORDERS[orderBy ?? "create_time desc"]);
    const page = Number.isFinite(size) && size > 0 ? matching.slice(offset, offset + size) : matching.slice(offset);
    const next = offset + page.length;
    return c.json({
      ...(page.length > 0 ? { alerts: page.map((alert) => alertResource(store, alert)) } : {}),
      ...(next < matching.length ? { nextPageToken: Buffer.from(String(next)).toString("base64url") } : {}),
    });
  });

  // "Attempting to get a nonexistent alert returns `NOT_FOUND` error."
  app.get(`${PREFIX}/alerts/:alertId`, (c) => {
    const refused = authorize(c, c.req.query("customerId"));
    if (refused) return refused;
    const alert = live(c.req.param("alertId") ?? "");
    return alert ? c.json(alertResource(store, alert)) : notFound(c);
  });

  app.get(`${PREFIX}/alerts/:alertId/metadata`, (c) => {
    const refused = authorize(c, c.req.query("customerId"));
    if (refused) return refused;
    const alert = live(c.req.param("alertId") ?? "");
    return alert ? c.json(alertMetadataResource(store, alert)) : notFound(c);
  });

  // "Marking an alert for deletion has no effect on an alert which has already been marked for deletion. Attempting
  // to mark a nonexistent alert for deletion results in a `NOT_FOUND` error."
  const markDeleted = (alert: GoogleAlert) => {
    if (alert.deleted) return;
    alert.deleted = true;
    alert.updateTime = new Date().toISOString();
  };
  // "Attempting to undelete an alert which has not been marked for deletion has no effect."
  const restore = (alert: GoogleAlert) => {
    if (!alert.deleted) return;
    alert.deleted = false;
    alert.updateTime = new Date().toISOString();
  };

  app.delete(`${PREFIX}/alerts/:alertId`, (c) => {
    const refused = authorize(c, c.req.query("customerId"));
    if (refused) return refused;
    const alert = live(c.req.param("alertId") ?? "");
    if (!alert) return notFound(c);
    markDeleted(alert);
    return c.json({});
  });

  const bodyCustomer = (body: Record<string, unknown>) =>
    typeof body.customerId === "string" ? body.customerId : undefined;

  // alerts.batchDelete and alerts.batchUndelete, `alerts:batchDelete` and `alerts:batchUndelete`.
  app.post(`${PREFIX}/:verb{alerts:batch(?:Delete|Undelete)}`, async (c) => {
    const body = await parseGoogleBody(c);
    const refused = authorize(c, bodyCustomer(body));
    if (refused) return refused;
    const deleting = c.req.param("verb") === "alerts:batchDelete";
    const ids = Array.isArray(body.alertId) ? body.alertId.filter((id): id is string => typeof id === "string") : [];
    const successAlertIds: string[] = [];
    const failedAlertStatus: Record<string, { code: number; message: string }> = {};
    for (const id of ids) {
      const alert = live(id);
      if (!alert) {
        // google.rpc.Status with code 5, `NOT_FOUND`.
        failedAlertStatus[id] = { code: 5, message: "Requested entity was not found." };
        continue;
      }
      if (deleting) markDeleted(alert);
      else restore(alert);
      successAlertIds.push(id);
    }
    return c.json({
      ...(successAlertIds.length > 0 ? { successAlertIds } : {}),
      ...(Object.keys(failedAlertStatus).length > 0 ? { failedAlertStatus } : {}),
    });
  });

  // alerts.undelete, `alerts/{alertId}:undelete`.
  app.post(`${PREFIX}/alerts/:target{[^/]+:undelete}`, async (c) => {
    const body = await parseGoogleBody(c);
    const refused = authorize(c, bodyCustomer(body));
    if (refused) return refused;
    const alert = live((c.req.param("target") ?? "").replace(/:undelete$/, ""));
    if (!alert) return notFound(c);
    restore(alert);
    return c.json(alertResource(store, alert));
  });

  const feedbackResource = (alert: GoogleAlert, feedback: GoogleAlert["feedback"][number]) => ({
    customerId: alertCustomerId(store),
    alertId: alert.alertId,
    feedbackId: feedback.feedbackId,
    createTime: feedback.createTime,
    type: feedback.type,
    email: feedback.email,
  });

  // "Attempting to create a feedback for a non-existent alert returns `NOT_FOUND` error. Attempting to create a
  // feedback for an alert that is marked for deletion returns `FAILED_PRECONDITION` error."
  app.post(`${PREFIX}/alerts/:alertId/feedback`, async (c) => {
    const refused = authorize(c, c.req.query("customerId"));
    if (refused) return refused;
    const alert = live(c.req.param("alertId") ?? "");
    if (!alert) return notFound(c);
    if (alert.deleted) {
      return googleApiError(c, 400, "The alert is marked for deletion.", "failedPrecondition", "FAILED_PRECONDITION");
    }
    const body = await parseGoogleBody(c);
    const type = typeof body.type === "string" ? body.type : "";
    if (!FEEDBACK_TYPES.has(type)) return invalid(c, "Invalid feedback type");
    const feedback = {
      feedbackId: randomUUID(),
      type,
      email: getAuthenticatedEmail(c) ?? "",
      createTime: new Date().toISOString(),
    };
    alert.feedback.push(feedback);
    return c.json(feedbackResource(alert, feedback));
  });

  // "Attempting to list feedbacks for a non-existent alert returns `NOT_FOUND` error."
  app.get(`${PREFIX}/alerts/:alertId/feedback`, (c) => {
    const refused = authorize(c, c.req.query("customerId"));
    if (refused) return refused;
    const alert = live(c.req.param("alertId") ?? "");
    if (!alert) return notFound(c);
    return c.json({ feedback: alert.feedback.map((feedback) => feedbackResource(alert, feedback)) });
  });

  // Customer-level settings: the Pub/Sub notifications the emulator keeps but does not deliver.
  app.get(`${PREFIX}/settings`, (c) => {
    const refused = authorize(c, c.req.query("customerId"));
    if (refused) return refused;
    return c.json(store.getData<Record<string, unknown>>("google.alert_settings") ?? {});
  });

  app.patch(`${PREFIX}/settings`, async (c) => {
    const refused = authorize(c, c.req.query("customerId"));
    if (refused) return refused;
    const body = await parseGoogleBody(c);
    const settings = Array.isArray(body.notifications) ? { notifications: body.notifications } : {};
    store.setData("google.alert_settings", settings);
    return c.json(settings);
  });
}
