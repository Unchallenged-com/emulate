import { randomUUID } from "node:crypto";
import type { Store } from "@emulators/core";
import { etagOf, getCustomerId } from "./directory.js";
import type { GoogleActivityEvent, GoogleUser } from "./entities.js";
import { getGoogleStore } from "./store.js";

// The alerts of the Alert Center API (https://developers.google.com/workspace/admin/alertcenter/reference/rest) that
// follow from what the emulator records: the predefined rules of the `UserChanges` bucket, and the super administrator
// password reset of `SensitiveAdminAction`
// (https://developers.google.com/workspace/admin/alertcenter/reference/alert-types).

const TYPE_URL = "type.googleapis.com/google.apps.alertcenter.type.";

/**
 * The `UserChanges` rules by the Admin event that meets their condition: each rule's name on the Admin console's Rules
 * page (https://knowledge.workspace.google.com/admin/reports/view-and-edit-system-defined-rules), and the alert's
 * `type` in the API. All seven are inactive by default, and only the Admin console turns them on, so the seed's
 * `alert_rules` names those that are on.
 */
const USER_CHANGES: Record<string, { rule: string; type: string }> = {
  CREATE_USER: { rule: "New user added", type: "New user Added" },
  UNSUSPEND_USER: { rule: "Suspended user made active", type: "Suspended user made active" },
  DELETE_USER: { rule: "User deleted", type: "User deleted" },
  GRANT_ADMIN_PRIVILEGE: { rule: "User granted Admin privilege", type: "User granted Admin privilege" },
  SUSPEND_USER: { rule: "User suspended (by admin)", type: "User suspended (Administrator email alert)" },
  REVOKE_ADMIN_PRIVILEGE: { rule: "User's Admin privilege revoked", type: "Users Admin privilege revoked" },
  CHANGE_PASSWORD: { rule: "User's password changed", type: "Users password changed" },
};

export const USER_CHANGES_RULES = Object.values(USER_CHANGES).map((entry) => entry.rule);

const RULES_KEY = "google.alert_rules";

export interface GoogleAlertFeedback {
  feedbackId: string;
  type: string;
  email: string;
  createTime: string;
}

export interface GoogleAlert {
  alertId: string;
  createTime: string;
  startTime: string;
  updateTime: string;
  type: string;
  source: string;
  data: Record<string, unknown>;
  deleted: boolean;
  status: string;
  assignee: string | null;
  feedback: GoogleAlertFeedback[];
}

function alerts(store: Store): Map<string, GoogleAlert> {
  let map = store.getData<Map<string, GoogleAlert>>("google.alerts");
  if (!map) {
    map = new Map();
    store.setData("google.alerts", map);
  }
  return map;
}

export function seedAlertRules(store: Store, rules: string[] | undefined): void {
  if (!rules) return;
  const unknown = rules.find((rule) => !USER_CHANGES_RULES.includes(rule));
  if (unknown)
    throw new Error(`google.alert_rules: unknown rule "${unknown}", expected one of ${USER_CHANGES_RULES.join(", ")}`);
  store.setData(RULES_KEY, [...rules]);
}

/** The Alert Center's `customerId`, the account's customer ID "with the initial "C" stripped". */
export function alertCustomerId(store: Store): string {
  return getCustomerId(store).replace(/^C/, "");
}

function raise(store: Store, source: string, type: string, data: Record<string, unknown>): void {
  const now = new Date().toISOString();
  // Chosen: an alert ID is a UUID, and the alert is there as soon as the event is (no delivery delay).
  const alertId = randomUUID();
  alerts(store).set(alertId, {
    alertId,
    createTime: now,
    startTime: now,
    updateTime: now,
    type,
    source,
    data,
    deleted: false,
    status: "NOT_STARTED",
    assignee: null,
    feedback: [],
  });
}

const parameter = (event: GoogleActivityEvent, name: string) => {
  const found = event.parameters.find((p) => p.name === name);
  return found && "value" in found ? found.value : undefined;
};

/**
 * The alerts an administrator's Directory change raises: a `UserChanges` alert for each change whose rule is on, with
 * the rule's name as `name` ("Rule name"), and the active "Super admin password reset" `SensitiveAdminAction` when the
 * password changed is a super administrator's.
 */
export function raiseAdminAlerts(store: Store, actor: GoogleUser, events: GoogleActivityEvent[]): void {
  const on = store.getData<string[]>(RULES_KEY) ?? [];
  for (const event of events) {
    const rule = USER_CHANGES[event.name];
    if (rule && on.includes(rule.rule)) {
      raise(store, "User Changes", rule.type, { "@type": `${TYPE_URL}UserChanges`, name: rule.rule });
    }
    const email = parameter(event, "USER_EMAIL");
    if (event.name === "CHANGE_PASSWORD" && email) {
      const target = getGoogleStore(store).users.findOneBy("email", email);
      if (target?.is_admin) {
        raise(store, "Sensitive Admin Action", "Super admin password reset", {
          "@type": `${TYPE_URL}SensitiveAdminAction`,
          actorEmail: actor.email,
          eventTime: new Date().toISOString(),
          superAdminPasswordResetEvent: { userEmail: email },
        });
      }
    }
  }
}

export function getAlert(store: Store, alertId: string): GoogleAlert | undefined {
  return alerts(store).get(alertId);
}

export function listAlerts(store: Store): GoogleAlert[] {
  return [...alerts(store).values()];
}

/** An alert's metadata. Chosen: `severity` is the empty string, the documented value "when it could not be determined". */
export function alertMetadataResource(store: Store, alert: GoogleAlert): Record<string, unknown> {
  const resource = {
    customerId: alertCustomerId(store),
    alertId: alert.alertId,
    status: alert.status,
    ...(alert.assignee ? { assignee: alert.assignee } : {}),
    updateTime: alert.updateTime,
    severity: "",
  };
  return { ...resource, etag: etagOf(resource) };
}

export function alertResource(store: Store, alert: GoogleAlert): Record<string, unknown> {
  const resource = {
    customerId: alertCustomerId(store),
    alertId: alert.alertId,
    createTime: alert.createTime,
    startTime: alert.startTime,
    updateTime: alert.updateTime,
    type: alert.type,
    source: alert.source,
    data: alert.data,
    ...(alert.deleted ? { deleted: true } : {}),
    metadata: alertMetadataResource(store, alert),
  };
  return { ...resource, etag: etagOf(resource) };
}
