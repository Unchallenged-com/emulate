import { createHash, randomBytes, randomUUID } from "node:crypto";
import { clientAddress, type AppEnv, type Context, type Store } from "@emulators/core";
import type { OktaApp, OktaGroup, OktaOAuthClient, OktaUser } from "./entities.js";
import { userDisplayName } from "./helpers.js";
import { getOktaStore } from "./store.js";

// Okta's System Log record, the LogEvent schema of the management API:
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/SystemLog/
// Key order, `version` "0", `client.zone` "null" and `device` follow records captured from Okta orgs.

export interface LogActor {
  id: string | null;
  type: string;
  alternateId: string | null;
  displayName: string | null;
  detailEntry: Record<string, unknown> | null;
}

export type LogTarget = LogActor;

export interface LogEvent {
  actor: LogActor;
  client: {
    userAgent: { rawUserAgent: string; os: string; browser: string } | null;
    zone: string;
    device: string | null;
    id: string | null;
    ipAddress: string | null;
    geographicalContext: null;
  };
  device: null;
  authenticationContext: {
    authenticationProvider: null;
    credentialProvider: null;
    credentialType: null;
    issuer: null;
    interface: null;
    authenticationStep: 0;
    externalSessionId: string | null;
    rootSessionId?: string;
  };
  displayMessage: string;
  eventType: string;
  outcome: { result: string; reason: string | null };
  published: string;
  securityContext: { asNumber: null; asOrg: null; isp: null; domain: null; isProxy: null };
  severity: "DEBUG" | "INFO" | "WARN" | "ERROR";
  debugContext: { debugData: Record<string, unknown> };
  legacyEventType: string | null;
  transaction: { type: "WEB" | "JOB"; id: string; detail: Record<string, unknown> };
  uuid: string;
  version: "0";
  request: { ipChain: Array<{ ip: string; geographicalContext: null; version: "V4" | "V6"; source: null }> };
  target: LogTarget[];
}

// Display messages and legacy event types. Where a captured record shows them they are taken from it; otherwise the
// display message is the event type's description in Okta's catalog
// (https://developer.okta.com/docs/reference/api/event-types/) and the legacy type is left null.
const EVENT_TYPES = {
  "user.session.start": { displayMessage: "User login to Okta", legacy: "core.user_auth.login_success" },
  "user.session.clear": { displayMessage: "Clear user session", legacy: null },
  "event_hook.created": {
    displayMessage: "Triggered when an event hook has been created",
    legacy: "platform.event_hook.created",
  },
  "event_hook.updated": {
    displayMessage: "Triggered when an event hook has been updated",
    legacy: "platform.event_hook.updated",
  },
  "event_hook.activated": {
    displayMessage: "Triggered when an event hook has been activated",
    legacy: "platform.event_hook.activated",
  },
  "event_hook.deactivated": {
    displayMessage: "Triggered when an event hook has been deactivated",
    legacy: "platform.event_hook.deactivated",
  },
  "event_hook.deleted": {
    displayMessage: "Triggered when an event hook has been deleted",
    legacy: "platform.event_hook.deleted",
  },
  "event_hook.verified": {
    displayMessage: "Triggered when attempting to verify an event hook",
    legacy: { SUCCESS: "platform.event_hook.verified.success", FAILURE: "platform.event_hook.verified.failure" },
  },
  "event_hook.delivery": {
    displayMessage: "Event Hook Delivery Failed",
    legacy: "platform.event_hook.delivered.failure",
  },
  "system.log_stream.lifecycle.create": {
    displayMessage: "Log stream created",
    legacy: "system.log_stream.lifecycle.create",
  },
  "system.log_stream.lifecycle.update": {
    displayMessage: "Log stream updated",
    legacy: "system.log_stream.lifecycle.update",
  },
  "system.log_stream.lifecycle.activate": {
    displayMessage: "Log stream activated",
    legacy: "system.log_stream.lifecycle.activate",
  },
  "system.log_stream.lifecycle.deactivate": {
    displayMessage: "Log stream deactivated",
    legacy: "system.log_stream.lifecycle.deactivate",
  },
  "system.log_stream.lifecycle.delete": {
    displayMessage: "Log stream deleted",
    legacy: "system.log_stream.lifecycle.delete",
  },
  "user.session.end": { displayMessage: "User logout from Okta", legacy: "core.user_auth.logout_success" },
  "app.generic.unauth_app_access_attempt": {
    displayMessage: "User attempted unauthorized access to app",
    legacy: "app.generic.unauth_app_access_attempt",
  },
  "user.authentication.sso": { displayMessage: "User single sign on to app", legacy: "app.auth.sso" },
  "app.oauth2.token.grant.access_token": {
    displayMessage: "OIDC access token is granted",
    legacy: "app.oauth2.token.grant.access_token_success",
  },
  "app.oauth2.as.token.grant.access_token": {
    displayMessage: "OAuth2 access token is granted",
    legacy: "app.oauth2.as.token.grant.access_token_success",
  },
  "app.oauth2.authorize.code": {
    displayMessage: "OIDC authorization code request",
    legacy: "app.oauth2.authorize.code_success",
  },
  "app.oauth2.as.authorize.code": {
    displayMessage: "OAuth2 authorization code request",
    legacy: "app.oauth2.as.authorize.code_success",
  },
  "app.oauth2.token.grant.id_token": {
    displayMessage: "OIDC id token is granted",
    legacy: "app.oauth2.token.grant.id_token_success",
  },
  "app.oauth2.as.token.grant.id_token": {
    displayMessage: "OAuth 2.0 ID token is granted",
    legacy: "app.oauth2.as.token.grant.id_token_success",
  },
  "app.oauth2.token.grant.refresh_token": {
    displayMessage: "OIDC refresh token is granted",
    legacy: "app.oauth2.token.grant.refresh_token_success",
  },
  "app.oauth2.as.token.grant.refresh_token": {
    displayMessage: "OAuth2 refresh token is granted",
    legacy: "app.oauth2.as.token.grant.refresh_token_success",
  },
  "app.oauth2.token.revoke": {
    displayMessage: "OIDC token revocation request",
    legacy: "app.oauth2.token.revoke_success",
  },
  "app.oauth2.as.token.revoke": {
    displayMessage: "OAuth2 token revocation request",
    legacy: "app.oauth2.as.token.revoke_success",
  },
  "oauth2.as.created": { displayMessage: "Authorization server is created.", legacy: "api.oauth2.as.created" },
  "oauth2.as.updated": { displayMessage: "Authorization server is updated.", legacy: "api.oauth2.as.updated" },
  "oauth2.as.activated": { displayMessage: "Authorization server is activated.", legacy: "api.oauth2.as.activated" },
  "oauth2.as.deactivated": {
    displayMessage: "Authorization server is deactivated.",
    legacy: "api.oauth2.as.deactivated",
  },
  "oauth2.as.deleted": { displayMessage: "Authorization server is deleted.", legacy: "api.oauth2.as.deleted" },
  "user.lifecycle.create": { displayMessage: "Create okta user", legacy: null },
  "user.lifecycle.activate": { displayMessage: "Activate Okta user", legacy: null },
  "user.lifecycle.deactivate": { displayMessage: "Deactivate Okta user", legacy: null },
  "user.lifecycle.suspend": { displayMessage: "Suspend Okta user", legacy: null },
  "user.lifecycle.unsuspend": { displayMessage: "Unsuspend Okta user", legacy: null },
  "user.lifecycle.reactivate": { displayMessage: "Reactivate Okta user", legacy: null },
  "user.lifecycle.delete.initiated": { displayMessage: "Delete Okta user initiated", legacy: null },
  "user.lifecycle.delete.completed": {
    displayMessage: "Delete Okta user completed",
    legacy: "core.user.config.user_status.delete.completed",
  },
  "user.account.update_profile": { displayMessage: "Update user profile for Okta", legacy: null },
  "group.lifecycle.create": { displayMessage: "Create okta group", legacy: null },
  "group.lifecycle.delete": { displayMessage: "Delete okta group", legacy: "group.lifecycle.delete" },
  "group.profile.update": { displayMessage: "Okta group profile updated", legacy: null },
  "group.user_membership.add": {
    displayMessage: "Add user to group membership",
    legacy: "core.user_group_member.user_add",
  },
  "group.user_membership.remove": { displayMessage: "Remove user from group membership", legacy: null },
  "application.lifecycle.create": { displayMessage: "Create application", legacy: null },
  "application.lifecycle.update": { displayMessage: "Update application", legacy: "app.generic.config.app_updated" },
  "application.lifecycle.activate": { displayMessage: "Activate application", legacy: null },
  "application.lifecycle.deactivate": { displayMessage: "Deactivate application", legacy: null },
  "application.lifecycle.delete": { displayMessage: "Delete application", legacy: null },
  "application.user_membership.add": {
    displayMessage: "Add user to application membership",
    legacy: "app.generic.provision.assign_user_to_app",
  },
  "application.user_membership.remove": { displayMessage: "Remove user's application membership", legacy: null },
} as const;

export type LogEventType = keyof typeof EVENT_TYPES;

export interface LogEventInput {
  eventType: LogEventType;
  actor: LogActor;
  target?: LogTarget[];
  /** The OAuth client making the request, for OAuth requests. */
  clientId?: string | null;
  externalSessionId?: string | null;
  rootSessionId?: string;
  debugData?: Record<string, unknown>;
  transactionDetail?: Record<string, unknown>;
  outcome?: { result: "SUCCESS" | "FAILURE"; reason?: string | null };
  severity?: LogEvent["severity"];
}

// One id per request: the events a request writes share their transaction and request ids.
const requestIds = new WeakMap<Request, string>();

function requestIdOf(c: Context<AppEnv>): string {
  let id = requestIds.get(c.req.raw);
  if (!id) {
    id = randomBytes(16).toString("hex");
    requestIds.set(c.req.raw, id);
  }
  return id;
}

/** A stable identifier for an API token, in the `00T` form of Okta's API token ids. */
export function apiTokenId(token: string): string {
  const digest = createHash("sha256").update(token).digest("base64url").replace(/[-_]/g, "");
  return `00T${digest.slice(0, 17)}`;
}

/** A token's id and hash as Okta logs them: `AT.` (access) or `ID.` (ID token) ids, and a 22 character hash. */
export function accessTokenIds(token: string, prefix: "AT" | "ID" | "RT" = "AT"): { id: string; hash: string } {
  const digest = createHash("sha256").update(token).digest();
  return { id: `${prefix}.${digest.toString("base64url")}`, hash: digest.subarray(0, 16).toString("base64url") };
}

/** A session id in Okta's form: `idx` for an Identity Engine sign-in, `trs` for an API call. */
export function sessionId(prefix: "idx" | "trs"): string {
  return `${prefix}${randomBytes(18).toString("base64url").slice(0, 22)}`;
}

function browserOf(ua: string): string {
  if (/Edg\//.test(ua)) return "EDGE_CHROMIUM";
  if (/Firefox\//.test(ua)) return "FIREFOX";
  if (/Chrome\//.test(ua)) return "CHROME";
  if (/Safari\//.test(ua) && /Version\//.test(ua)) return "SAFARI";
  return "UNKNOWN";
}

function osOf(ua: string): string {
  if (/iPhone|iPad/.test(ua)) return "iOS";
  if (/Android/.test(ua)) return "Android";
  if (/Windows NT/.test(ua)) return "Windows";
  if (/Mac OS X/.test(ua)) return "Mac OS X";
  if (/Linux/.test(ua)) return "Linux";
  return "Unknown";
}

function deviceOf(ua: string, browser: string): string {
  if (browser === "UNKNOWN") return "Unknown";
  return /Mobile|iPhone|Android/.test(ua) ? "Mobile" : "Computer";
}

/** Records one System Log event for the request being handled. */
// Some legacy types depend on the outcome.
function legacyOf(legacy: string | null | { SUCCESS: string; FAILURE: string }, result: string): string | null {
  if (legacy === null || typeof legacy === "string") return legacy;
  return result === "FAILURE" ? legacy.FAILURE : legacy.SUCCESS;
}

// Listeners told of each event recorded in a store, such as event hook delivery.
const logListeners = new WeakMap<Store, Array<(event: LogEvent) => void>>();

export function onLogEvent(store: Store, listener: (event: LogEvent) => void): void {
  logListeners.set(store, [...(logListeners.get(store) ?? []), listener]);
}

/**
 * Records one System Log event for the request being handled, or, with no request (`c` null), for work Okta does
 * on its own, recorded as a JOB.
 */
export function recordLogEvent(store: Store, c: Context<AppEnv> | null, input: LogEventInput): LogEvent {
  const known = EVENT_TYPES[input.eventType];
  const requestId = c ? requestIdOf(c) : randomBytes(16).toString("hex");
  const ip = c ? (clientAddress(c.req.raw) ?? null) : null;
  const url = c ? new URL(c.req.url) : null;
  const rawUserAgent = c?.req.header("User-Agent");
  const browser = rawUserAgent ? browserOf(rawUserAgent) : "UNKNOWN";

  const transactionDetail: Record<string, unknown> = { ...input.transactionDetail };

  const authenticationContext: LogEvent["authenticationContext"] = {
    authenticationProvider: null,
    credentialProvider: null,
    credentialType: null,
    issuer: null,
    interface: null,
    authenticationStep: 0,
    externalSessionId: input.externalSessionId ?? null,
  };
  if (input.rootSessionId !== undefined) authenticationContext.rootSessionId = input.rootSessionId;

  const event: LogEvent = {
    actor: input.actor,
    client: {
      userAgent: rawUserAgent ? { rawUserAgent, os: osOf(rawUserAgent), browser } : null,
      zone: "null",
      device: rawUserAgent ? deviceOf(rawUserAgent, browser) : null,
      id: input.clientId ?? null,
      ipAddress: ip,
      geographicalContext: null,
    },
    device: null,
    authenticationContext,
    displayMessage: known.displayMessage,
    eventType: input.eventType,
    outcome: { result: input.outcome?.result ?? "SUCCESS", reason: input.outcome?.reason ?? null },
    published: new Date().toISOString(),
    securityContext: { asNumber: null, asOrg: null, isp: null, domain: null, isProxy: null },
    severity: input.severity ?? "INFO",
    debugContext: {
      debugData: url
        ? { requestId, requestUri: url.pathname, url: `${url.pathname}${url.search}`, ...input.debugData }
        : { requestId, ...input.debugData },
    },
    legacyEventType: legacyOf(known.legacy, input.outcome?.result ?? "SUCCESS"),
    transaction: { type: c ? "WEB" : "JOB", id: requestId, detail: transactionDetail },
    uuid: randomUUID(),
    version: "0",
    request: {
      ipChain: ip ? [{ ip, geographicalContext: null, version: ip.includes(":") ? "V6" : "V4", source: null }] : [],
    },
    target: input.target ?? [],
  };

  getOktaStore(store).logEvents.insert({ uuid: event.uuid, published: event.published, event });
  for (const listener of logListeners.get(store) ?? []) listener(event);
  return event;
}

/** The actor of what Okta does on its own. */
export const SYSTEM_PRINCIPAL: LogActor = {
  id: "spr_emulate_system",
  type: "SystemPrincipal",
  alternateId: "system@okta.com",
  displayName: "Okta System",
  detailEntry: null,
};

export function userEntity(user: OktaUser): LogActor {
  return {
    id: user.okta_id,
    type: "User",
    alternateId: user.login,
    displayName: userDisplayName(user),
    detailEntry: null,
  };
}

export function groupTarget(group: OktaGroup): LogTarget {
  return { id: group.okta_id, type: "UserGroup", alternateId: "unknown", displayName: group.name, detailEntry: null };
}

export function appTarget(app: OktaApp, detailEntry: Record<string, unknown> | null = null): LogTarget {
  return { id: app.okta_id, type: "AppInstance", alternateId: app.label, displayName: app.label, detailEntry };
}

export function appUserTarget(user: OktaUser): LogTarget {
  return { ...userEntity(user), type: "AppUser" };
}

export function oauthClientActor(clientId: string, client: OktaOAuthClient | undefined): LogActor {
  return {
    id: clientId,
    type: "PublicClientApp",
    alternateId: clientId,
    displayName: client?.name ?? clientId,
    detailEntry: null,
  };
}

/**
 * Records an event of a management API call: the actor is the Okta user the token belongs to, since API tokens act
 * as the administrator who created them.
 */
export function recordManagementEvent(
  store: Store,
  c: Context<AppEnv>,
  auth: { login: string },
  eventType: LogEventType,
  target: LogTarget[],
  debugData?: Record<string, unknown>,
  outcome?: { result: "SUCCESS" | "FAILURE"; reason?: string | null },
): void {
  const okta = getOktaStore(store);
  const authorization = c.req.header("Authorization") ?? "";
  const token = authorization.replace(/^(ssws|bearer)\s+/i, "").trim();
  const user = okta.users.findOneBy("login", auth.login);
  const client = user ? undefined : okta.oauthClients.findOneBy("client_id", auth.login);

  let actor: LogActor;
  const transactionDetail: Record<string, unknown> = {};
  if (client && /^bearer\s+/i.test(authorization)) {
    // A service app calling with a client credentials access token.
    actor = {
      id: client.client_id,
      type: "PublicClientAppEntity",
      alternateId: "unknown",
      displayName: client.name,
      detailEntry: null,
    };
    const { id } = accessTokenIds(token);
    transactionDetail.requestApiTokenClientId = client.client_id;
    transactionDetail.requestApiTokenId = id;
    transactionDetail.rootApiTokenId = id;
  } else {
    actor = user
      ? userEntity(user)
      : { id: null, type: "User", alternateId: auth.login, displayName: auth.login, detailEntry: null };
    if (/^ssws\s+/i.test(authorization)) transactionDetail.requestApiTokenId = apiTokenId(token);
  }
  recordLogEvent(store, c, {
    eventType,
    actor,
    target,
    externalSessionId: managementSessionId(c),
    transactionDetail,
    debugData,
    outcome,
  });
}

// The events of one management call share the `trs` session id Okta gives API calls.
const managementSessions = new WeakMap<Request, string>();

function managementSessionId(c: Context<AppEnv>): string {
  let id = managementSessions.get(c.req.raw);
  if (!id) {
    id = sessionId("trs");
    managementSessions.set(c.req.raw, id);
  }
  return id;
}

export function authorizationServerTarget(server: { server_id: string; name: string; description: string }): LogTarget {
  return {
    id: server.server_id,
    type: "AuthorizationServerEntity",
    alternateId: "unknown",
    displayName: server.name,
    detailEntry: { authorizationserverdescription: server.description },
  };
}
