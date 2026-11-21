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

/** A standard administrator role assigned to a user. */
export interface OktaRoleAssignment extends Entity {
  assignment_id: string;
  user_okta_id: string;
  type: string;
}

/** An API token (`SSWS`), kept by the hash of its value. */
export interface OktaApiToken extends Entity {
  token_id: string;
  token_hash: string;
  name: string;
  user_okta_id: string;
  last_used_at: string;
}
