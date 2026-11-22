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

/** An event hook; `auth_value` is the secret of its authentication header, never returned. */
export interface OktaEventHook extends Entity {
  hook_id: string;
  name: string;
  description: string | null;
  status: "ACTIVE" | "INACTIVE";
  verification_status: "UNVERIFIED" | "VERIFIED";
  created_by: string | null;
  event_types: string[];
  uri: string;
  headers: Array<{ key: string; value: string }>;
  auth_key: string | null;
  auth_value: string | null;
}

/** A log stream; `settings` holds the type's write-only values too (the Splunk HEC token), never returned. */
export interface OktaLogStream extends Entity {
  stream_id: string;
  type: "aws_eventbridge" | "splunk_cloud_logstreaming";
  name: string;
  status: "ACTIVE" | "INACTIVE";
  settings: Record<string, string>;
}
