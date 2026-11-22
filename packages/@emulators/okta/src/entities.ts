import type { Entity } from "@emulators/core";
import type { LogEvent } from "./system-log.js";

export type OktaUserStatus = "STAGED" | "PROVISIONED" | "ACTIVE" | "SUSPENDED" | "DEPROVISIONED";

export interface OktaUser extends Entity {
  okta_id: string;
  status: OktaUserStatus;
  activated_at: string | null;
  status_changed_at: string;
  last_login_at: string | null;
  password_changed_at: string | null;
  transitioning_to_status: OktaUserStatus | null;
  login: string;
  email: string;
  first_name: string;
  last_name: string;
  display_name: string;
  locale: string;
  time_zone: string;
}

export type OktaGroupType = "OKTA_GROUP" | "BUILT_IN";

export interface OktaGroup extends Entity {
  okta_id: string;
  type: OktaGroupType;
  name: string;
  description: string | null;
}

export type OktaAppStatus = "ACTIVE" | "INACTIVE";

export interface OktaApp extends Entity {
  okta_id: string;
  name: string;
  label: string;
  status: OktaAppStatus;
  sign_on_mode: string;
  settings: Record<string, unknown>;
  credentials: Record<string, unknown>;
}

export interface OktaOAuthClient extends Entity {
  client_id: string;
  client_secret?: string;
  name: string;
  redirect_uris: string[];
  response_types: string[];
  grant_types: string[];
  token_endpoint_auth_method: "client_secret_post" | "client_secret_basic" | "none";
  auth_server_id: string;
}

export type OktaAuthorizationServerStatus = "ACTIVE" | "INACTIVE";

export interface OktaAuthorizationServer extends Entity {
  server_id: string;
  name: string;
  description: string;
  audiences: string[];
  status: OktaAuthorizationServerStatus;
}

export interface OktaGroupMembership extends Entity {
  group_okta_id: string;
  user_okta_id: string;
}

export interface OktaAppAssignment extends Entity {
  app_okta_id: string;
  user_okta_id: string;
}

/** A System Log event, kept in the order it was recorded (its `id`). */
export interface OktaLogEventEntry extends Entity {
  uuid: string;
  published: string;
  event: LogEvent;
}

/** A policy; its type-specific `conditions` and `settings` are kept as given. */
export interface OktaPolicy extends Entity {
  policy_id: string;
  type: string;
  name: string;
  description: string | null;
  status: "ACTIVE" | "INACTIVE";
  priority: number;
  conditions: Record<string, unknown> | null;
  settings: Record<string, unknown> | null;
}

/** A rule of a policy; its `conditions` and `actions` are kept as given. */
export interface OktaPolicyRule extends Entity {
  rule_id: string;
  policy_id: string;
  type: string;
  name: string;
  status: "ACTIVE" | "INACTIVE";
  priority: number;
  conditions: Record<string, unknown> | null;
  actions: Record<string, unknown> | null;
}

/** A network zone; the fields of its type (`gateways`, `proxies`, `asns`, `locations`, ...) are kept as given. */
export interface OktaNetworkZone extends Entity {
  zone_id: string;
  type: "IP" | "DYNAMIC" | "DYNAMIC_V2";
  name: string;
  status: "ACTIVE" | "INACTIVE";
  usage: "POLICY" | "BLOCKLIST";
  fields: Record<string, unknown>;
}
