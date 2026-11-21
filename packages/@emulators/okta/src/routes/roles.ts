import type { AppEnv, Context, RouteContext, Store } from "@emulators/core";
import { generateOktaId } from "../helpers.js";
import { findUserByRef, oktaError, readJsonObject, requireManagementAuth } from "../route-helpers.js";
import { getOktaStore } from "../store.js";
import { recordManagementEvent, userEntity } from "../system-log.js";
import type { OktaRoleAssignment, OktaUser } from "../entities.js";

// Standard role assignments to users:
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignmentAUser/
// Labels are the standard roles' names in https://developer.okta.com/docs/api/openapi/okta-management/guides/roles/
export const STANDARD_ROLES: Record<string, string> = {
  API_ACCESS_MANAGEMENT_ADMIN: "API Access Management Administrator",
  APP_ADMIN: "Application Administrator",
  GROUP_MEMBERSHIP_ADMIN: "Group Membership Administrator",
  HELP_DESK_ADMIN: "Help Desk Administrator",
  ORG_ADMIN: "Organization Administrator",
  READ_ONLY_ADMIN: "Read-only Administrator",
  REPORT_ADMIN: "Report Administrator",
  SUPER_ADMIN: "Super Administrator",
  USER_ADMIN: "Group Administrator",
};

// How System Log records name each privilege in `privilegeGranted` and `privilegeRevoked`, as captured records
// write them (unscoped roles, so application and user administrators apply to all).
const PRIVILEGE_NAMES: Record<string, string> = {
  API_ACCESS_MANAGEMENT_ADMIN: "API Access Management administrator",
  APP_ADMIN: "Application administrator (all)",
  GROUP_MEMBERSHIP_ADMIN: "Group Membership administrator",
  HELP_DESK_ADMIN: "Help Desk administrator",
  ORG_ADMIN: "Organization administrator",
  READ_ONLY_ADMIN: "Read only admin",
  REPORT_ADMIN: "Report administrator",
  SUPER_ADMIN: "Super administrator",
  USER_ADMIN: "User administrator (all)",
};

function roleResponse(baseUrl: string, role: OktaRoleAssignment): Record<string, unknown> {
  return {
    id: role.assignment_id,
    label: STANDARD_ROLES[role.type] ?? role.type,
    type: role.type,
    status: "ACTIVE",
    created: role.created_at,
    lastUpdated: role.updated_at,
    assignmentType: "USER",
    _links: {
      assignee: { href: `${baseUrl}/api/v1/users/${encodeURIComponent(role.user_okta_id)}` },
    },
  };
}

/**
 * Records a change of a user's administrator roles. `user.account.privilege.grant` lists the privileges the user
 * holds after the change; `user.account.privilege.revoke` means the user has none left, and lists those revoked
 * (https://developer.okta.com/docs/reference/api/event-types/).
 */
function recordPrivilegeChange(
  store: Store,
  c: Context<AppEnv>,
  auth: { login: string },
  user: OktaUser,
  removed?: OktaRoleAssignment,
): void {
  const held = getOktaStore(store).roleAssignments.findBy("user_okta_id", user.okta_id);
  if (held.length === 0 && removed) {
    recordManagementEvent(store, c, auth, "user.account.privilege.revoke", [userEntity(user)], {
      privilegeRevoked: PRIVILEGE_NAMES[removed.type],
    });
  } else {
    recordManagementEvent(store, c, auth, "user.account.privilege.grant", [userEntity(user)], {
      privilegeGranted: held.map((role) => PRIVILEGE_NAMES[role.type]).join(", "),
    });
  }
}

export function roleRoutes({ app, store, baseUrl, tokenMap }: RouteContext): void {
  const oktaStore = getOktaStore(store);

  app.get("/api/v1/users/:userId/roles", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");
    return c.json(
      oktaStore.roleAssignments.findBy("user_okta_id", user.okta_id).map((role) => roleResponse(baseUrl, role)),
    );
  });

  app.post("/api/v1/users/:userId/roles", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");

    const body = await readJsonObject(c);
    const type = typeof body.type === "string" ? body.type : "";
    if (!STANDARD_ROLES[type]) {
      return oktaError(c, 400, "E0000001", "Api validation failed: type", [
        { errorSummary: `type: '${type}' is not a standard role type the emulator supports` },
      ]);
    }
    const held = oktaStore.roleAssignments.findBy("user_okta_id", user.okta_id);
    if (held.some((role) => role.type === type)) {
      return oktaError(c, 409, "E0000090", "The role specified is already assigned to the user.");
    }

    const created = oktaStore.roleAssignments.insert({
      assignment_id: generateOktaId("ra"),
      user_okta_id: user.okta_id,
      type,
    });
    recordPrivilegeChange(store, c, auth, user);
    return c.json(roleResponse(baseUrl, created), 201);
  });

  app.get("/api/v1/users/:userId/roles/:roleAssignmentId", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");
    const role = oktaStore.roleAssignments
      .findBy("user_okta_id", user.okta_id)
      .find((entry) => entry.assignment_id === c.req.param("roleAssignmentId"));
    if (!role) return oktaError(c, 404, "E0000007", "Not found: role assignment");
    return c.json(roleResponse(baseUrl, role));
  });

  app.delete("/api/v1/users/:userId/roles/:roleAssignmentId", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");
    const role = oktaStore.roleAssignments
      .findBy("user_okta_id", user.okta_id)
      .find((entry) => entry.assignment_id === c.req.param("roleAssignmentId"));
    if (!role) return oktaError(c, 404, "E0000007", "Not found: role assignment");

    oktaStore.roleAssignments.delete(role.id);
    recordPrivilegeChange(store, c, auth, user, role);
    return c.body(null, 204);
  });
}
