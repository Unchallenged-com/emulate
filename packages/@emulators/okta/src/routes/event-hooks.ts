import { randomBytes, randomUUID } from "node:crypto";
import type { AppEnv, Context, RouteContext, Store } from "@emulators/core";
import type { OktaEventHook } from "../entities.js";
import { generateOktaId } from "../helpers.js";
import { oktaError, readJsonObject, requireManagementAuth } from "../route-helpers.js";
import { getOktaStore } from "../store.js";
import {
  SYSTEM_PRINCIPAL,
  onLogEvent,
  recordLogEvent,
  recordManagementEvent,
  type LogEvent,
  type LogEventType,
  type LogTarget,
} from "../system-log.js";

// Event hooks: the Event Hooks API (https://developer.okta.com/docs/api/openapi/okta-management/management/tag/EventHook/)
// and the delivery protocol (https://developer.okta.com/docs/concepts/event-hooks/).

// "If a response is not received within 3 seconds, the outbound request times out. One retry is attempted after a
// timeout or error response."
const TIMEOUT_MS = 3000;

// The event types the emulator records that Okta's catalog marks `event-hook-eligible`. Hooks may subscribe to any
// type; only these are delivered.
const ELIGIBLE = new Set([
  "user.session.start",
  "user.session.end",
  "user.session.clear",
  "user.authentication.sso",
  "user.lifecycle.create",
  "user.lifecycle.activate",
  "user.lifecycle.deactivate",
  "user.lifecycle.suspend",
  "user.lifecycle.unsuspend",
  "user.lifecycle.reactivate",
  "user.lifecycle.delete.initiated",
  "user.account.update_profile",
  "group.lifecycle.create",
  "group.lifecycle.delete",
  "group.profile.update",
  "group.user_membership.add",
  "group.user_membership.remove",
  "application.lifecycle.create",
  "application.lifecycle.update",
  "application.lifecycle.activate",
  "application.lifecycle.deactivate",
  "application.lifecycle.delete",
  "application.user_membership.add",
  "application.user_membership.remove",
  "system.log_stream.lifecycle.create",
  "system.log_stream.lifecycle.update",
  "system.log_stream.lifecycle.activate",
  "system.log_stream.lifecycle.deactivate",
  "system.log_stream.lifecycle.delete",
]);

// Okta requires an HTTPS endpoint; the emulator also accepts plain HTTP on the loopback interface, for local tests.
function acceptableUri(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.protocol === "https:") return true;
    return url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  } catch {
    return false;
  }
}

function hookHeaders(hook: OktaEventHook): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const header of hook.headers) headers[header.key] = header.value;
  if (hook.auth_key && hook.auth_value) headers[hook.auth_key] = hook.auth_value;
  return headers;
}

/** One request with Okta's timeout; `undefined` when it timed out or could not be sent. */
async function send(url: string, init: RequestInit): Promise<Response | undefined> {
  try {
    return await fetch(url, { ...init, signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch {
    return undefined;
  }
}

function hookTarget(hook: OktaEventHook): LogTarget {
  return { id: hook.hook_id, type: "EventHook", alternateId: "unknown", displayName: hook.name, detailEntry: null };
}

export function eventHookResponse(baseUrl: string, hook: OktaEventHook): Record<string, unknown> {
  const href = `${baseUrl}/api/v1/eventHooks/${encodeURIComponent(hook.hook_id)}`;
  const links: Record<string, unknown> =
    hook.status === "ACTIVE"
      ? {
          self: { href },
          verify: { href: `${href}/lifecycle/verify`, hints: { allow: ["POST"] } },
          deactivate: { href: `${href}/lifecycle/deactivate`, hints: { allow: ["POST"] } },
        }
      : {
          activate: { href: `${href}/lifecycle/activate`, hints: { allow: ["POST"] } },
          self: { href },
          delete: { href, hints: { allow: ["DELETE"] } },
        };
  return {
    id: hook.hook_id,
    status: hook.status,
    verificationStatus: hook.verification_status,
    name: hook.name,
    description: hook.description,
    created: hook.created_at,
    createdBy: hook.created_by,
    lastUpdated: hook.updated_at,
    events: { type: "EVENT_TYPE", items: hook.event_types, filter: null },
    channel: {
      type: "HTTP",
      version: "1.0.0",
      config: {
        uri: hook.uri,
        headers: hook.headers,
        method: "POST",
        // The secret value is write-only.
        ...(hook.auth_key ? { authScheme: { type: "HEADER", key: hook.auth_key } } : {}),
      },
    },
    _links: links,
  };
}

/** Delivers the eligible events recorded in a store to its active, verified hooks, batched per tick. */
function startDelivery(store: Store, baseUrl: string): void {
  const pending = new Map<string, LogEvent[]>();
  let scheduled = false;

  const deliver = async (hook: OktaEventHook, events: LogEvent[]) => {
    const body = JSON.stringify({
      eventType: "com.okta.event_hook",
      eventTypeVersion: "1.0",
      cloudEventsVersion: "0.1",
      source: `${baseUrl}/api/v1/eventHooks/${hook.hook_id}`,
      eventId: randomUUID(),
      data: { events },
      eventTime: new Date().toISOString(),
      contentType: "application/json",
    });
    const init: RequestInit = {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json", ...hookHeaders(hook) },
      body,
    };
    // "Responses with a 4xx status code aren't retried. Response with a 5xx status code are retried."
    let response = await send(hook.uri, init);
    if (!response || response.status >= 500) response = await send(hook.uri, init);
    if (response && response.ok) return;
    const reason = response
      ? `${response.status} ${response.statusText}. Exceeded maximum retry limit of 1`
      : "Request timed out. Exceeded maximum retry limit of 1";
    recordLogEvent(store, null, {
      eventType: "event_hook.delivery",
      actor: SYSTEM_PRINCIPAL,
      target: [hookTarget(hook)],
      outcome: { result: "FAILURE", reason },
      severity: "WARN",
    });
  };

  const flush = () => {
    scheduled = false;
    const batches = [...pending.entries()];
    pending.clear();
    for (const [hookId, events] of batches) {
      const hook = getOktaStore(store).eventHooks.findOneBy("hook_id", hookId);
      if (hook) void deliver(hook, events);
    }
  };

  onLogEvent(store, (event) => {
    if (!ELIGIBLE.has(event.eventType)) return;
    const hooks = getOktaStore(store)
      .eventHooks.all()
      .filter(
        (hook) =>
          hook.status === "ACTIVE" &&
          hook.verification_status === "VERIFIED" &&
          hook.event_types.includes(event.eventType),
      );
    for (const hook of hooks) pending.set(hook.hook_id, [...(pending.get(hook.hook_id) ?? []), event]);
    if (hooks.length > 0 && !scheduled) {
      scheduled = true;
      setTimeout(flush, 0);
    }
  });
}

export function eventHookRoutes({ app, store, baseUrl, tokenMap }: RouteContext): void {
  const oktaStore = getOktaStore(store);
  startDelivery(store, baseUrl);

  const hookOf = (c: Context<AppEnv>) => oktaStore.eventHooks.findOneBy("hook_id", c.req.param("eventHookId"));
  const notFound = (c: Context<AppEnv>) => oktaError(c, 404, "E0000007", "Not found: event hook");
  const invalid = (c: Context<AppEnv>, cause: string) =>
    oktaError(c, 400, "E0000001", "Api validation failed: eventHook", [{ errorSummary: cause }]);
  const record = (c: Context<AppEnv>, auth: { login: string }, eventType: LogEventType, hook: OktaEventHook) =>
    recordManagementEvent(store, c, auth, eventType, [hookTarget(hook)]);

  // The parts of a hook a create or replace request sets, or the cause of its refusal.
  const parse = (body: Record<string, unknown>) => {
    const name = typeof body.name === "string" ? body.name.trim() : "";
    const events = body.events as { type?: unknown; items?: unknown } | undefined;
    const items = Array.isArray(events?.items)
      ? events.items.filter((item): item is string => typeof item === "string")
      : [];
    const config = (body.channel as { config?: Record<string, unknown> } | undefined)?.config ?? {};
    const uri = typeof config.uri === "string" ? config.uri : "";
    if (!name) return "name: The field cannot be left blank";
    if (items.length === 0) return "events.items: The field cannot be left blank";
    if (!acceptableUri(uri)) return "channel.config.uri: The event hook must use a valid HTTPS endpoint";
    const headers = Array.isArray(config.headers)
      ? (config.headers as Array<{ key?: unknown; value?: unknown }>)
          .filter((header) => typeof header.key === "string" && typeof header.value === "string")
          .map((header) => ({ key: header.key as string, value: header.value as string }))
      : [];
    const auth = config.authScheme as { key?: unknown; value?: unknown } | undefined;
    return {
      name,
      description: typeof body.description === "string" ? body.description : null,
      event_types: items,
      uri,
      headers,
      auth_key: typeof auth?.key === "string" ? auth.key : null,
      auth_value: typeof auth?.value === "string" ? auth.value : null,
    };
  };

  app.get("/api/v1/eventHooks", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    return c.json(oktaStore.eventHooks.all().map((hook) => eventHookResponse(baseUrl, hook)));
  });

  app.post("/api/v1/eventHooks", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const parsed = parse(await readJsonObject(c));
    if (typeof parsed === "string") return invalid(c, parsed);
    // "Creates a new event hook for your organization in ACTIVE status"; it receives events once verified.
    const hook = oktaStore.eventHooks.insert({
      hook_id: generateOktaId("who"),
      status: "ACTIVE",
      verification_status: "UNVERIFIED",
      created_by: oktaStore.users.findOneBy("login", auth.login)?.okta_id ?? null,
      ...parsed,
    });
    record(c, auth, "event_hook.created", hook);
    return c.json(eventHookResponse(baseUrl, hook));
  });

  app.get("/api/v1/eventHooks/:eventHookId", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const hook = hookOf(c);
    if (!hook) return notFound(c);
    return c.json(eventHookResponse(baseUrl, hook));
  });

  app.put("/api/v1/eventHooks/:eventHookId", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const hook = hookOf(c);
    if (!hook) return notFound(c);
    const parsed = parse(await readJsonObject(c));
    if (typeof parsed === "string") return invalid(c, parsed);
    // "Updating the channel property requires you to verify the hook again."
    const channelChanged =
      parsed.uri !== hook.uri ||
      JSON.stringify(parsed.headers) !== JSON.stringify(hook.headers) ||
      parsed.auth_key !== hook.auth_key ||
      (parsed.auth_value !== null && parsed.auth_value !== hook.auth_value);
    const updated =
      oktaStore.eventHooks.update(hook.id, {
        ...parsed,
        auth_value: parsed.auth_value ?? hook.auth_value,
        verification_status: channelChanged ? "UNVERIFIED" : hook.verification_status,
      }) ?? hook;
    record(c, auth, "event_hook.updated", updated);
    return c.json(eventHookResponse(baseUrl, updated));
  });

  app.delete("/api/v1/eventHooks/:eventHookId", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const hook = hookOf(c);
    if (!hook) return notFound(c);
    // "As a safety precaution, you can only delete event hooks with a status of INACTIVE."
    if (hook.status !== "INACTIVE") {
      return oktaError(c, 403, "E0000107", "The entity is not in the expected state for the requested transition.");
    }
    oktaStore.eventHooks.delete(hook.id);
    record(c, auth, "event_hook.deleted", hook);
    return c.body(null, 204);
  });

  for (const [path, status, eventType] of [
    ["activate", "ACTIVE", "event_hook.activated"],
    ["deactivate", "INACTIVE", "event_hook.deactivated"],
  ] as const) {
    app.post(`/api/v1/eventHooks/:eventHookId/lifecycle/${path}`, (c) => {
      const auth = requireManagementAuth(c, tokenMap);
      if (auth instanceof Response) return auth;
      const hook = hookOf(c);
      if (!hook) return notFound(c);
      const updated = oktaStore.eventHooks.update(hook.id, { status }) ?? hook;
      record(c, auth, eventType, updated);
      return c.json(eventHookResponse(baseUrl, updated));
    });
  }

  app.post("/api/v1/eventHooks/:eventHookId/lifecycle/verify", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const hook = hookOf(c);
    if (!hook) return notFound(c);

    // One-time verification: a GET carrying a challenge the endpoint must echo as {"verification": ...}.
    const challenge = randomBytes(24).toString("base64url");
    const init: RequestInit = {
      method: "GET",
      headers: { Accept: "application/json", ...hookHeaders(hook), "x-okta-verification-challenge": challenge },
    };
    const verified = async () => {
      const response = await send(hook.uri, init);
      if (!response?.ok) return false;
      const answer = (await response.json().catch(() => null)) as { verification?: unknown } | null;
      return answer?.verification === challenge;
    };
    const ok = (await verified()) || (await verified());

    recordManagementEvent(store, c, auth, "event_hook.verified", [hookTarget(hook)], undefined, {
      result: ok ? "SUCCESS" : "FAILURE",
    });
    if (!ok) {
      return invalid(c, `Unable to verify event hook. Hook ${hook.name} execution failed`);
    }
    const updated = oktaStore.eventHooks.update(hook.id, { verification_status: "VERIFIED" }) ?? hook;
    return c.json(eventHookResponse(baseUrl, updated));
  });
}
