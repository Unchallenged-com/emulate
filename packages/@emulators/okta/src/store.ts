import { Store, type Collection } from "@emulators/core";
import type {
  OktaUser,
  OktaGroup,
  OktaApp,
  OktaOAuthClient,
  OktaAuthorizationServer,
  OktaGroupMembership,
  OktaAppAssignment,
  OktaLogEventEntry,
  OktaPolicy,
  OktaPolicyRule,
  OktaNetworkZone,
} from "./entities.js";

export interface OktaStore {
  users: Collection<OktaUser>;
  groups: Collection<OktaGroup>;
  apps: Collection<OktaApp>;
  oauthClients: Collection<OktaOAuthClient>;
  authorizationServers: Collection<OktaAuthorizationServer>;
  groupMemberships: Collection<OktaGroupMembership>;
  appAssignments: Collection<OktaAppAssignment>;
  logEvents: Collection<OktaLogEventEntry>;
  policies: Collection<OktaPolicy>;
  policyRules: Collection<OktaPolicyRule>;
  zones: Collection<OktaNetworkZone>;
}

export function getOktaStore(store: Store): OktaStore {
  return {
    users: store.collection<OktaUser>("okta.users", ["okta_id", "login", "email"]),
    groups: store.collection<OktaGroup>("okta.groups", ["okta_id", "name"]),
    apps: store.collection<OktaApp>("okta.apps", ["okta_id", "name"]),
    oauthClients: store.collection<OktaOAuthClient>("okta.oauth_clients", ["client_id", "auth_server_id"]),
    authorizationServers: store.collection<OktaAuthorizationServer>("okta.auth_servers", ["server_id"]),
    groupMemberships: store.collection<OktaGroupMembership>("okta.group_memberships", [
      "group_okta_id",
      "user_okta_id",
    ]),
    appAssignments: store.collection<OktaAppAssignment>("okta.app_assignments", ["app_okta_id", "user_okta_id"]),
    logEvents: store.collection<OktaLogEventEntry>("okta.log_events", ["uuid"]),
    policies: store.collection<OktaPolicy>("okta.policies", ["policy_id", "type"]),
    policyRules: store.collection<OktaPolicyRule>("okta.policy_rules", ["rule_id", "policy_id"]),
    zones: store.collection<OktaNetworkZone>("okta.zones", ["zone_id", "name"]),
  };
}
