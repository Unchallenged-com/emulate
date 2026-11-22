import type { AppEnv, Context, RouteContext } from "@emulators/core";
import type { OktaNetworkZone } from "../entities.js";
import { generateOktaId } from "../helpers.js";
import { oktaError, readJsonObject, requireManagementAuth } from "../route-helpers.js";
import { getOktaStore } from "../store.js";
import { recordManagementEvent, type LogEventType, type LogTarget } from "../system-log.js";

// Network zones: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/NetworkZone/
// The emulator stores them and does not match sign-ins or API calls against them.

const ZONE_TYPES = new Set(["IP", "DYNAMIC", "DYNAMIC_V2"]);
// The fields of each zone type, kept as given.
const TYPE_FIELDS: Record<string, string[]> = {
  IP: ["gateways", "proxies", "useAsExemptList"],
  DYNAMIC: ["asns", "locations", "proxyType"],
  DYNAMIC_V2: ["asns", "locations", "ipServiceCategories"],
};

function zoneFields(type: string, body: Record<string, unknown>): Record<string, unknown> {
  const fields: Record<string, unknown> = {};
  for (const key of TYPE_FIELDS[type] ?? []) if (key in body) fields[key] = body[key];
  return fields;
}

// "For an IP Network Zone, you must define either gateways or proxies. For a Dynamic Network Zone, you must define at
// least one of the following: asns, locations, or proxyType."
function missingDefinition(type: string, fields: Record<string, unknown>): boolean {
  const defined = (key: string) =>
    Array.isArray(fields[key]) ? (fields[key] as unknown[]).length > 0 : fields[key] != null;
  if (type === "IP") return !defined("gateways") && !defined("proxies");
  if (type === "DYNAMIC") return !defined("asns") && !defined("locations") && !defined("proxyType");
  return !defined("asns") && !defined("locations") && !defined("ipServiceCategories");
}

export function zoneResponse(baseUrl: string, zone: OktaNetworkZone): Record<string, unknown> {
  const href = `${baseUrl}/api/v1/zones/${encodeURIComponent(zone.zone_id)}`;
  return {
    type: zone.type,
    id: zone.zone_id,
    name: zone.name,
    status: zone.status,
    usage: zone.usage,
    created: zone.created_at,
    lastUpdated: zone.updated_at,
    system: false,
    ...zone.fields,
    _links: {
      self: { href, hints: { allow: ["GET", "PUT", "DELETE"] } },
      ...(zone.status === "ACTIVE"
        ? { deactivate: { href: `${href}/lifecycle/deactivate`, hints: { allow: ["POST"] } } }
        : { activate: { href: `${href}/lifecycle/activate`, hints: { allow: ["POST"] } } }),
    },
  };
}

function zoneTarget(zone: OktaNetworkZone): LogTarget {
  return {
    id: zone.zone_id,
    type: "NetworkZoneEntity",
    alternateId: "unknown",
    displayName: zone.name,
    detailEntry: null,
  };
}

export function zoneRoutes({ app, store, baseUrl, tokenMap }: RouteContext): void {
  const oktaStore = getOktaStore(store);
  const zoneOf = (c: Context<AppEnv>) => oktaStore.zones.findOneBy("zone_id", c.req.param("zoneId"));
  // Every zone event carries the zone's definition in `zoneData`, as a JSON string (the catalog's
  // NetworkZoneDebugData).
  const record = (c: Context<AppEnv>, auth: { login: string }, eventType: LogEventType, zone: OktaNetworkZone) =>
    recordManagementEvent(store, c, auth, eventType, [zoneTarget(zone)], {
      zoneData: JSON.stringify({ type: zone.type, ...zone.fields }),
    });

  const invalid = (c: Context<AppEnv>, cause: string) =>
    oktaError(c, 400, "E0000001", "Api validation failed: zone", [{ errorSummary: cause }]);

  app.get("/api/v1/zones", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    return c.json(oktaStore.zones.all().map((zone) => zoneResponse(baseUrl, zone)));
  });

  app.post("/api/v1/zones", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonObject(c);
    const type = typeof body.type === "string" ? body.type : "";
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!ZONE_TYPES.has(type)) return invalid(c, "type: The network zone type is not valid");
    if (!name) return invalid(c, "name: The field cannot be left blank");
    const fields = zoneFields(type, body);
    if (missingDefinition(type, fields)) return invalid(c, "The network zone defines no addresses or locations");
    const zone = oktaStore.zones.insert({
      zone_id: generateOktaId("nzo"),
      type: type as OktaNetworkZone["type"],
      name,
      status: "ACTIVE",
      usage: body.usage === "BLOCKLIST" ? "BLOCKLIST" : "POLICY",
      fields,
    });
    record(c, auth, "zone.create", zone);
    return c.json(zoneResponse(baseUrl, zone));
  });

  app.get("/api/v1/zones/:zoneId", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const zone = zoneOf(c);
    if (!zone) return oktaError(c, 404, "E0000007", "Not found: zone");
    return c.json(zoneResponse(baseUrl, zone));
  });

  app.put("/api/v1/zones/:zoneId", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const zone = zoneOf(c);
    if (!zone) return oktaError(c, 404, "E0000007", "Not found: zone");
    const body = await readJsonObject(c);
    // "The replaced Network Zone type must be the same as the existing type."
    if (typeof body.type === "string" && body.type !== zone.type) return invalid(c, "type: The type cannot be changed");
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!name) return invalid(c, "name: The field cannot be left blank");
    const fields = zoneFields(zone.type, body);
    if (missingDefinition(zone.type, fields)) return invalid(c, "The network zone defines no addresses or locations");
    const updated =
      oktaStore.zones.update(zone.id, {
        name,
        usage: body.usage === "BLOCKLIST" ? "BLOCKLIST" : body.usage === "POLICY" ? "POLICY" : zone.usage,
        fields,
      }) ?? zone;
    record(c, auth, "zone.update", updated);
    return c.json(zoneResponse(baseUrl, updated));
  });

  app.delete("/api/v1/zones/:zoneId", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const zone = zoneOf(c);
    if (!zone) return oktaError(c, 404, "E0000007", "Not found: zone");
    // "For Okta Identity Engine orgs, you can't delete a Network Zone with an ACTIVE status."
    if (zone.status === "ACTIVE") {
      return oktaError(c, 403, "E0000107", "The entity is not in the expected state for the requested transition.");
    }
    oktaStore.zones.delete(zone.id);
    record(c, auth, "zone.delete", zone);
    return c.body(null, 204);
  });

  for (const [path, status, eventType] of [
    ["activate", "ACTIVE", "zone.activate"],
    ["deactivate", "INACTIVE", "zone.deactivate"],
  ] as const) {
    app.post(`/api/v1/zones/:zoneId/lifecycle/${path}`, (c) => {
      const auth = requireManagementAuth(c, tokenMap);
      if (auth instanceof Response) return auth;
      const zone = zoneOf(c);
      if (!zone) return oktaError(c, 404, "E0000007", "Not found: zone");
      const updated = oktaStore.zones.update(zone.id, { status }) ?? zone;
      record(c, auth, eventType, updated);
      return c.json(zoneResponse(baseUrl, updated));
    });
  }
}
