import type { AppEnv, Context, RouteContext } from "@emulators/core";
import type { OktaLogStream } from "../entities.js";
import { generateOktaId } from "../helpers.js";
import { oktaError, readJsonObject, requireManagementAuth } from "../route-helpers.js";
import { getOktaStore } from "../store.js";
import { recordManagementEvent, type LogEventType, type LogTarget } from "../system-log.js";

// Log streams: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/LogStream/
// The emulator stores them and records their changes; it does not send events to AWS EventBridge or Splunk Cloud.

// The settings of each type and their rules, from the log stream schemas of Okta's API
// (`/api/v1/meta/schemas/logStream/{type}`) and its AwsRegion enum.
const AWS_REGIONS = new Set([
  "ap-northeast-1",
  "ap-northeast-2",
  "ap-northeast-3",
  "ap-south-1",
  "ap-southeast-1",
  "ap-southeast-2",
  "ca-central-1",
  "eu-central-1",
  "eu-north-1",
  "eu-west-1",
  "eu-west-2",
  "eu-west-3",
  "sa-east-1",
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2",
]);
const SPLUNK_EDITIONS = new Set(["aws", "aws_govcloud", "gcp"]);
const HEC_TOKEN = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

type Settings = Record<string, string>;

function settingsOf(value: unknown): Settings {
  const settings: Settings = {};
  if (value && typeof value === "object") {
    for (const [key, entry] of Object.entries(value)) if (typeof entry === "string") settings[key] = entry;
  }
  return settings;
}

// The cause of a refusal, or null when the settings are valid for the type.
function invalidSettings(type: string, settings: Settings): string | null {
  if (type === "aws_eventbridge") {
    if (!/^\d{12}$/.test(settings.accountId ?? "")) return "settings.accountId: Your Amazon AWS Account ID.";
    if (!/^[.\-_A-Za-z0-9]{1,75}$/.test(settings.eventSourceName ?? "")) {
      return "settings.eventSourceName: An alphanumeric name (no spaces) to identify this event source in AWS EventBridge.";
    }
    if (!AWS_REGIONS.has(settings.region ?? "")) return "settings.region: The destination AWS region.";
    return null;
  }
  if (!/^([a-z0-9]+(-[a-z0-9]+)*){1,100}\.splunkcloud(gc|fed)?\.com$/.test(settings.host ?? "")) {
    return "settings.host: The domain for your Splunk Cloud instance without http or https.";
  }
  if (!SPLUNK_EDITIONS.has(settings.edition ?? ""))
    return "settings.edition: The edition of the Splunk Cloud instance.";
  return null;
}

// What a response shows of the settings: everything but the write-only Splunk HEC token.
function visibleSettings(stream: OktaLogStream): Settings {
  const { token: _token, ...visible } = stream.settings;
  return visible;
}

export function logStreamResponse(baseUrl: string, stream: OktaLogStream): Record<string, unknown> {
  const href = `${baseUrl}/api/v1/logStreams/${encodeURIComponent(stream.stream_id)}`;
  return {
    id: stream.stream_id,
    type: stream.type,
    name: stream.name,
    lastUpdated: stream.updated_at,
    created: stream.created_at,
    status: stream.status,
    settings: visibleSettings(stream),
    _links: {
      self: { href, method: "GET" },
      ...(stream.status === "ACTIVE"
        ? { deactivate: { href: `${href}/lifecycle/deactivate`, method: "POST" } }
        : { activate: { href: `${href}/lifecycle/activate`, method: "POST" } }),
    },
  };
}

function streamTarget(stream: OktaLogStream): LogTarget {
  return {
    id: stream.stream_id,
    type: "LogStream",
    alternateId: "unknown",
    displayName: stream.name,
    detailEntry: null,
  };
}

export function logStreamRoutes({ app, store, baseUrl, tokenMap }: RouteContext): void {
  const oktaStore = getOktaStore(store);
  const streamOf = (c: Context<AppEnv>) => oktaStore.logStreams.findOneBy("stream_id", c.req.param("logStreamId"));
  const notFound = (c: Context<AppEnv>) => oktaError(c, 404, "E0000007", "Not found: log stream");
  const invalid = (c: Context<AppEnv>, cause: string) =>
    oktaError(c, 400, "E0000001", "Api validation failed: logStream", [{ errorSummary: cause }]);
  const record = (c: Context<AppEnv>, auth: { login: string }, eventType: LogEventType, stream: OktaLogStream) =>
    recordManagementEvent(store, c, auth, eventType, [streamTarget(stream)]);

  app.get("/api/v1/logStreams", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    return c.json(oktaStore.logStreams.all().map((stream) => logStreamResponse(baseUrl, stream)));
  });

  app.post("/api/v1/logStreams", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonObject(c);
    const type = body.type;
    if (type !== "aws_eventbridge" && type !== "splunk_cloud_logstreaming") {
      return invalid(c, "type: The log stream type is not valid");
    }
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!name) return invalid(c, "name: The field cannot be left blank");
    const settings = settingsOf(body.settings);
    const cause = invalidSettings(type, settings);
    if (cause) return invalid(c, cause);
    if (type === "splunk_cloud_logstreaming" && !HEC_TOKEN.test(settings.token ?? "")) {
      return invalid(c, "settings.token: The token from your Splunk Cloud HTTP Event Collector (HEC).");
    }
    // A new log stream is ACTIVE.
    const stream = oktaStore.logStreams.insert({
      stream_id: generateOktaId("0oa"),
      type,
      name,
      status: "ACTIVE",
      settings,
    });
    record(c, auth, "system.log_stream.lifecycle.create", stream);
    return c.json(logStreamResponse(baseUrl, stream));
  });

  app.get("/api/v1/logStreams/:logStreamId", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const stream = streamOf(c);
    if (!stream) return notFound(c);
    return c.json(logStreamResponse(baseUrl, stream));
  });

  app.put("/api/v1/logStreams/:logStreamId", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const stream = streamOf(c);
    if (!stream) return notFound(c);
    const body = await readJsonObject(c);
    if (body.type !== undefined && body.type !== stream.type) return invalid(c, "type: The type cannot be changed");
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!name) return invalid(c, "name: The field cannot be left blank");
    const requested = settingsOf(body.settings);
    // AWS EventBridge settings are all write-once; Splunk Cloud takes a new host and edition, and keeps its token.
    if (stream.type === "aws_eventbridge") {
      const changed = Object.entries(requested).some(([key, value]) => stream.settings[key] !== value);
      if (changed) return invalid(c, "settings: The AWS EventBridge settings can't be changed once set");
    }
    const settings = stream.type === "aws_eventbridge" ? stream.settings : { ...stream.settings, ...requested };
    const cause = invalidSettings(stream.type, settings);
    if (cause) return invalid(c, cause);
    const updated = oktaStore.logStreams.update(stream.id, { name, settings }) ?? stream;
    record(c, auth, "system.log_stream.lifecycle.update", updated);
    return c.json(logStreamResponse(baseUrl, updated));
  });

  app.delete("/api/v1/logStreams/:logStreamId", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const stream = streamOf(c);
    if (!stream) return notFound(c);
    oktaStore.logStreams.delete(stream.id);
    record(c, auth, "system.log_stream.lifecycle.delete", stream);
    return c.body(null, 204);
  });

  for (const [path, status, eventType] of [
    ["activate", "ACTIVE", "system.log_stream.lifecycle.activate"],
    ["deactivate", "INACTIVE", "system.log_stream.lifecycle.deactivate"],
  ] as const) {
    app.post(`/api/v1/logStreams/:logStreamId/lifecycle/${path}`, (c) => {
      const auth = requireManagementAuth(c, tokenMap);
      if (auth instanceof Response) return auth;
      const stream = streamOf(c);
      if (!stream) return notFound(c);
      const updated = oktaStore.logStreams.update(stream.id, { status }) ?? stream;
      record(c, auth, eventType, updated);
      // Recorded answers of Okta are 200 with an empty body here.
      return c.body(null, 200);
    });
  }
}
