import type { AppEnv, Context, RouteContext, Store } from "@emulators/core";
import type { OktaPolicy, OktaPolicyRule } from "../entities.js";
import { boolFromQuery, generateOktaId } from "../helpers.js";
import { oktaError, readJsonObject, requireManagementAuth } from "../route-helpers.js";
import { getOktaStore } from "../store.js";
import { recordManagementEvent, type LogEventType, type LogTarget } from "../system-log.js";

// Policies and their rules: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/
// The emulator stores them, with their type-specific conditions, settings and actions as given, and does not
// enforce them at sign-in.

const POLICY_TYPES = new Set([
  "ACCESS_POLICY",
  "ENTITY_RISK",
  "IDP_DISCOVERY",
  "MFA_ENROLL",
  "OKTA_SIGN_ON",
  "PASSWORD",
  "POST_AUTH_SESSION",
  "PROFILE_ENROLLMENT",
  "DEVICE_SIGNAL_COLLECTION",
  "SESSION_VIOLATION_DETECTION",
  "CLIENT_UPDATE",
  "IDENTITY_CLAIM_SOURCING",
]);

// "You can't create additional rules for the PROFILE_ENROLLMENT, POST_AUTH_SESSION, CLIENT_UPDATE, or
// IDENTITY_CLAIM_SOURCING policies."
const NO_ADDITIONAL_RULES = new Set([
  "PROFILE_ENROLLMENT",
  "POST_AUTH_SESSION",
  "CLIENT_UPDATE",
  "IDENTITY_CLAIM_SOURCING",
]);

// A sign-on policy's rules are SIGN_ON rules; every other rule type is its policy's type.
function ruleTypeOf(policyType: string): string {
  return policyType === "OKTA_SIGN_ON" ? "SIGN_ON" : policyType;
}

// Identity Engine's rule-set policies (app sign-in and profile enrollment) take `rst` and `rul` ids, as in Okta's
// examples and captured records; the others `00p` and `0pr`.
const RULE_SET_TYPES = new Set(["ACCESS_POLICY", "PROFILE_ENROLLMENT"]);

function newPolicyId(type: string): string {
  return generateOktaId(RULE_SET_TYPES.has(type) ? "rst" : "00p");
}

function newRuleId(type: string): string {
  return generateOktaId(RULE_SET_TYPES.has(type) ? "rul" : "0pr");
}

function objectOrNull(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function lifecycleLinks(href: string, status: string): Record<string, unknown> {
  return status === "ACTIVE"
    ? { deactivate: { href: `${href}/lifecycle/deactivate`, hints: { allow: ["POST"] } } }
    : { activate: { href: `${href}/lifecycle/activate`, hints: { allow: ["POST"] } } };
}

export function policyResponse(baseUrl: string, policy: OktaPolicy): Record<string, unknown> {
  const href = `${baseUrl}/api/v1/policies/${encodeURIComponent(policy.policy_id)}`;
  return {
    type: policy.type,
    id: policy.policy_id,
    status: policy.status,
    name: policy.name,
    description: policy.description,
    priority: policy.priority,
    system: false,
    created: policy.created_at,
    lastUpdated: policy.updated_at,
    conditions: policy.conditions,
    ...(policy.settings ? { settings: policy.settings } : {}),
    _links: {
      self: { href, hints: { allow: ["GET", "PUT", "DELETE"] } },
      rules: { href: `${href}/rules`, hints: { allow: ["POST", "GET"] } },
      ...lifecycleLinks(href, policy.status),
    },
  };
}

export function ruleResponse(baseUrl: string, rule: OktaPolicyRule): Record<string, unknown> {
  const href = `${baseUrl}/api/v1/policies/${encodeURIComponent(rule.policy_id)}/rules/${encodeURIComponent(rule.rule_id)}`;
  return {
    id: rule.rule_id,
    status: rule.status,
    name: rule.name,
    priority: rule.priority,
    created: rule.created_at,
    lastUpdated: rule.updated_at,
    system: false,
    conditions: rule.conditions,
    actions: rule.actions,
    type: rule.type,
    _links: {
      self: { href, hints: { allow: ["GET", "PUT", "DELETE"] } },
      ...lifecycleLinks(href, rule.status),
    },
  };
}

// The policy type names System Log records carry in the target's `policyType`, from the catalog's
// PolicyResourceDetails; types it does not list keep their API name.
const LOGGED_POLICY_TYPES: Record<string, string> = {
  OKTA_SIGN_ON: "OktaSignOn",
  PASSWORD: "Password",
  MFA_ENROLL: "OktaMfaEnroll",
  IDP_DISCOVERY: "IdpDiscovery",
};

// Rule-set policies and their rules are RuleSetEntity and RuleEntity targets in captured records; the others
// PolicyEntity and PolicyRule, with the policy id as the rule's alternate id.
function policyTarget(policy: OktaPolicy, changeDetails?: LogTarget["changeDetails"]): LogTarget {
  return {
    id: policy.policy_id,
    type: RULE_SET_TYPES.has(policy.type) ? "RuleSetEntity" : "PolicyEntity",
    alternateId: "unknown",
    displayName: policy.name,
    detailEntry: { policyType: LOGGED_POLICY_TYPES[policy.type] ?? policy.type },
    ...(changeDetails ? { changeDetails } : {}),
  };
}

function ruleTarget(policy: OktaPolicy, rule: OktaPolicyRule): LogTarget {
  const ruleSet = RULE_SET_TYPES.has(policy.type);
  return {
    id: rule.rule_id,
    type: ruleSet ? "RuleEntity" : "PolicyRule",
    alternateId: ruleSet ? "unknown" : rule.policy_id,
    displayName: rule.name,
    detailEntry: null,
  };
}

// The properties of the catalog's PolicyChangeDetailsEntry that a replacement changed, written in the camelCase of
// System Log fields (the catalog spells them policy_name, policy_description, policy_priority,
// policy_group_include_size).
function policyChangeDetails(before: OktaPolicy, after: OktaPolicy): LogTarget["changeDetails"] | undefined {
  const includeSize = (policy: OktaPolicy) => {
    const include = (policy.conditions?.people as { groups?: { include?: unknown } } | undefined)?.groups?.include;
    return Array.isArray(include) ? include.length : 0;
  };
  const values = (policy: OktaPolicy): Record<string, unknown> => ({
    policyName: policy.name,
    policyDescription: policy.description,
    policyPriority: policy.priority,
    policyGroupIncludeSize: includeSize(policy),
  });
  const from = values(before);
  const to = values(after);
  const changed = Object.keys(to).filter((key) => from[key] !== to[key]);
  if (changed.length === 0) return undefined;
  return {
    from: Object.fromEntries(changed.map((key) => [key, from[key]])),
    to: Object.fromEntries(changed.map((key) => [key, to[key]])),
  };
}

function recordPolicyEvent(
  store: Store,
  c: Context<AppEnv>,
  auth: { login: string },
  eventType: LogEventType,
  policy: OktaPolicy,
  rule?: OktaPolicyRule,
  changeDetails?: LogTarget["changeDetails"],
): void {
  // A rule's events name its policy first, then the rule.
  const target = rule ? [policyTarget(policy), ruleTarget(policy, rule)] : [policyTarget(policy, changeDetails)];
  recordManagementEvent(store, c, auth, eventType, target);
}

export function policyRoutes({ app, store, baseUrl, tokenMap }: RouteContext): void {
  const oktaStore = getOktaStore(store);
  const notFound = (c: Context<AppEnv>, what: string) => oktaError(c, 404, "E0000007", `Not found: ${what}`);

  const policyOf = (c: Context<AppEnv>) => oktaStore.policies.findOneBy("policy_id", c.req.param("policyId"));
  const ruleOf = (c: Context<AppEnv>, policy: OktaPolicy) =>
    oktaStore.policyRules.findBy("policy_id", policy.policy_id).find((rule) => rule.rule_id === c.req.param("ruleId"));

  app.get("/api/v1/policies", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const type = c.req.query("type") ?? "";
    if (!POLICY_TYPES.has(type)) {
      return oktaError(c, 400, "E0000001", "Api validation failed: type", [
        { errorSummary: "type: The policy type is required" },
      ]);
    }
    const status = c.req.query("status");
    const q = c.req.query("q");
    const policies = oktaStore.policies
      .findBy("type", type)
      .filter((policy) => !status || policy.status === status)
      .filter((policy) => !q || policy.name.startsWith(q))
      .sort((a, b) => a.priority - b.priority);
    return c.json(policies.map((policy) => policyResponse(baseUrl, policy)));
  });

  app.post("/api/v1/policies", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonObject(c);
    const type = typeof body.type === "string" ? body.type : "";
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!POLICY_TYPES.has(type) || !name) {
      return oktaError(c, 400, "E0000001", "Api validation failed: policy", [
        { errorSummary: !name ? "name: The field cannot be left blank" : "type: The policy type is not valid" },
      ]);
    }
    const sameType = oktaStore.policies.findBy("type", type);
    const policy = oktaStore.policies.insert({
      policy_id: newPolicyId(type),
      type,
      name,
      description: typeof body.description === "string" ? body.description : null,
      status: boolFromQuery(c.req.query("activate"), true) && body.status !== "INACTIVE" ? "ACTIVE" : "INACTIVE",
      priority: typeof body.priority === "number" ? body.priority : sameType.length + 1,
      conditions: objectOrNull(body.conditions),
      settings: objectOrNull(body.settings),
    });
    recordPolicyEvent(store, c, auth, "policy.lifecycle.create", policy);
    return c.json(policyResponse(baseUrl, policy));
  });

  app.get("/api/v1/policies/:policyId", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const policy = policyOf(c);
    if (!policy) return notFound(c, "policy");
    return c.json(policyResponse(baseUrl, policy));
  });

  app.put("/api/v1/policies/:policyId", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const policy = policyOf(c);
    if (!policy) return notFound(c, "policy");
    const body = await readJsonObject(c);
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!name) {
      return oktaError(c, 400, "E0000001", "Api validation failed: policy", [
        { errorSummary: "name: The field cannot be left blank" },
      ]);
    }
    const updated =
      oktaStore.policies.update(policy.id, {
        name,
        description: typeof body.description === "string" ? body.description : null,
        priority: typeof body.priority === "number" ? body.priority : policy.priority,
        conditions: objectOrNull(body.conditions),
        settings: objectOrNull(body.settings),
      }) ?? policy;
    recordPolicyEvent(
      store,
      c,
      auth,
      "policy.lifecycle.update",
      updated,
      undefined,
      policyChangeDetails(policy, updated),
    );
    return c.json(policyResponse(baseUrl, updated));
  });

  app.delete("/api/v1/policies/:policyId", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const policy = policyOf(c);
    if (!policy) return notFound(c, "policy");
    for (const rule of oktaStore.policyRules.findBy("policy_id", policy.policy_id))
      oktaStore.policyRules.delete(rule.id);
    oktaStore.policies.delete(policy.id);
    recordPolicyEvent(store, c, auth, "policy.lifecycle.delete", policy);
    return c.body(null, 204);
  });

  for (const [path, status, eventType] of [
    ["activate", "ACTIVE", "policy.lifecycle.activate"],
    ["deactivate", "INACTIVE", "policy.lifecycle.deactivate"],
  ] as const) {
    app.post(`/api/v1/policies/:policyId/lifecycle/${path}`, (c) => {
      const auth = requireManagementAuth(c, tokenMap);
      if (auth instanceof Response) return auth;
      const policy = policyOf(c);
      if (!policy) return notFound(c, "policy");
      const updated = oktaStore.policies.update(policy.id, { status }) ?? policy;
      recordPolicyEvent(store, c, auth, eventType, updated);
      return c.body(null, 204);
    });
  }

  app.get("/api/v1/policies/:policyId/rules", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const policy = policyOf(c);
    if (!policy) return notFound(c, "policy");
    const rules = oktaStore.policyRules.findBy("policy_id", policy.policy_id).sort((a, b) => a.priority - b.priority);
    return c.json(rules.map((rule) => ruleResponse(baseUrl, rule)));
  });

  app.post("/api/v1/policies/:policyId/rules", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const policy = policyOf(c);
    if (!policy) return notFound(c, "policy");
    if (NO_ADDITIONAL_RULES.has(policy.type)) {
      return oktaError(c, 400, "E0000001", "Api validation failed: rule", [
        { errorSummary: `You can't create additional rules for ${policy.type} policies` },
      ]);
    }
    const body = await readJsonObject(c);
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!name) {
      return oktaError(c, 400, "E0000001", "Api validation failed: rule", [
        { errorSummary: "name: The field cannot be left blank" },
      ]);
    }
    const siblings = oktaStore.policyRules.findBy("policy_id", policy.policy_id);
    const rule = oktaStore.policyRules.insert({
      rule_id: newRuleId(policy.type),
      policy_id: policy.policy_id,
      type: ruleTypeOf(policy.type),
      name,
      status: boolFromQuery(c.req.query("activate"), true) && body.status !== "INACTIVE" ? "ACTIVE" : "INACTIVE",
      priority: typeof body.priority === "number" ? body.priority : siblings.length + 1,
      conditions: objectOrNull(body.conditions),
      actions: objectOrNull(body.actions),
    });
    recordPolicyEvent(store, c, auth, "policy.rule.add", policy, rule);
    return c.json(ruleResponse(baseUrl, rule));
  });

  app.get("/api/v1/policies/:policyId/rules/:ruleId", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const policy = policyOf(c);
    if (!policy) return notFound(c, "policy");
    const rule = ruleOf(c, policy);
    if (!rule) return notFound(c, "rule");
    return c.json(ruleResponse(baseUrl, rule));
  });

  app.put("/api/v1/policies/:policyId/rules/:ruleId", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const policy = policyOf(c);
    if (!policy) return notFound(c, "policy");
    const rule = ruleOf(c, policy);
    if (!rule) return notFound(c, "rule");
    const body = await readJsonObject(c);
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!name) {
      return oktaError(c, 400, "E0000001", "Api validation failed: rule", [
        { errorSummary: "name: The field cannot be left blank" },
      ]);
    }
    const updated =
      oktaStore.policyRules.update(rule.id, {
        name,
        priority: typeof body.priority === "number" ? body.priority : rule.priority,
        conditions: objectOrNull(body.conditions),
        actions: objectOrNull(body.actions),
      }) ?? rule;
    recordPolicyEvent(store, c, auth, "policy.rule.update", policy, updated);
    return c.json(ruleResponse(baseUrl, updated));
  });

  app.delete("/api/v1/policies/:policyId/rules/:ruleId", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const policy = policyOf(c);
    if (!policy) return notFound(c, "policy");
    const rule = ruleOf(c, policy);
    if (!rule) return notFound(c, "rule");
    oktaStore.policyRules.delete(rule.id);
    recordPolicyEvent(store, c, auth, "policy.rule.delete", policy, rule);
    return c.body(null, 204);
  });

  for (const [path, status, eventType] of [
    ["activate", "ACTIVE", "policy.rule.activate"],
    ["deactivate", "INACTIVE", "policy.rule.deactivate"],
  ] as const) {
    app.post(`/api/v1/policies/:policyId/rules/:ruleId/lifecycle/${path}`, (c) => {
      const auth = requireManagementAuth(c, tokenMap);
      if (auth instanceof Response) return auth;
      const policy = policyOf(c);
      if (!policy) return notFound(c, "policy");
      const rule = ruleOf(c, policy);
      if (!rule) return notFound(c, "rule");
      const updated = oktaStore.policyRules.update(rule.id, { status }) ?? rule;
      recordPolicyEvent(store, c, auth, eventType, policy, updated);
      return c.body(null, 204);
    });
  }
}
