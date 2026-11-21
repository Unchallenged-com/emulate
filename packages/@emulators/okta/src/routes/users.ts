import { parsePagination, setLinkHeader, type RouteContext } from "@emulators/core";
import { boolFromQuery, generateOktaId, nowIso, userDisplayName } from "../helpers.js";
import { findUserByRef, oktaError, readJsonObject, requireManagementAuth, userResponse } from "../route-helpers.js";
import { getOktaStore } from "../store.js";
import { revokeUserOAuthTokens } from "./oauth.js";
import { revokeUserApiTokens } from "../api-tokens.js";
import type { OktaUser, OktaUserStatus } from "../entities.js";
import { groupTarget, recordManagementEvent, userEntity, type LogEventType } from "../system-log.js";

function updateUserProfile(user: OktaUser, profile: Record<string, unknown>): Partial<OktaUser> {
  const nextFirstName = typeof profile.firstName === "string" ? profile.firstName : user.first_name;
  const nextLastName = typeof profile.lastName === "string" ? profile.lastName : user.last_name;
  const nextDisplayName =
    typeof profile.displayName === "string"
      ? profile.displayName
      : typeof profile.nickName === "string"
        ? profile.nickName
        : user.display_name;

  return {
    login: typeof profile.login === "string" ? profile.login : user.login,
    email: typeof profile.email === "string" ? profile.email : user.email,
    first_name: nextFirstName,
    last_name: nextLastName,
    display_name: nextDisplayName || `${nextFirstName} ${nextLastName}`.trim(),
    locale: typeof profile.locale === "string" ? profile.locale : user.locale,
    time_zone: typeof profile.timeZone === "string" ? profile.timeZone : user.time_zone,
  };
}

function setLifecycleStatus(user: OktaUser, target: OktaUserStatus): Partial<OktaUser> {
  const now = nowIso();
  const activatedAt = target === "ACTIVE" ? (user.activated_at ?? now) : user.activated_at;
  return {
    status: target,
    transitioning_to_status: null,
    status_changed_at: now,
    activated_at: activatedAt,
  };
}

export function userRoutes({ app, store, baseUrl, tokenMap }: RouteContext): void {
  const oktaStore = getOktaStore(store);

  const lifecycle = (path: string, target: OktaUserStatus, eventType: LogEventType) => {
    app.post(`/api/v1/users/:userId/lifecycle/${path}`, (c) => {
      const auth = requireManagementAuth(c, tokenMap);
      if (auth instanceof Response) return auth;
      const user = findUserByRef(oktaStore, c.req.param("userId"));
      if (!user) return oktaError(c, 404, "E0000007", "Not found: user");
      const updated = oktaStore.users.update(user.id, setLifecycleStatus(user, target)) ?? user;
      // Deactivating a user deprovisions the API tokens they created.
      if (target === "DEPROVISIONED") revokeUserApiTokens(store, user.okta_id);
      recordManagementEvent(store, c, auth, eventType, [userEntity(updated)]);
      return c.json(userResponse(baseUrl, updated));
    });
  };

  app.get("/api/v1/users", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;

    const q = (c.req.query("q") ?? "").toLowerCase();
    const search = (c.req.query("search") ?? "").toLowerCase();
    const filter = c.req.query("filter") ?? "";

    let users = oktaStore.users.all();

    if (q) {
      users = users.filter((user) =>
        [user.login, user.email, user.first_name, user.last_name, user.display_name]
          .join(" ")
          .toLowerCase()
          .includes(q),
      );
    }

    if (search) {
      users = users.filter((user) =>
        [user.login, user.email, user.first_name, user.last_name, user.display_name]
          .join(" ")
          .toLowerCase()
          .includes(search),
      );
    }

    if (filter) {
      const statusMatch = filter.match(/status\s+eq\s+"?([A-Z_]+)"?/i);
      if (statusMatch?.[1]) {
        users = users.filter((user) => user.status === statusMatch[1]);
      }
    }

    const { page, per_page } = parsePagination(c);
    const total = users.length;
    const start = (page - 1) * per_page;
    const paged = users.slice(start, start + per_page);
    setLinkHeader(c, total, page, per_page);
    c.header("X-Total-Count", String(total));

    return c.json(paged.map((user) => userResponse(baseUrl, user)));
  });

  app.post("/api/v1/users", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;

    const body = await readJsonObject(c);
    const profile = (body.profile && typeof body.profile === "object" ? body.profile : {}) as Record<string, unknown>;
    const login = typeof profile.login === "string" ? profile.login.trim() : "";
    const email = typeof profile.email === "string" ? profile.email.trim() : login;

    if (!login || !email) {
      return oktaError(c, 400, "E0000001", "profile.login and profile.email are required");
    }

    if (oktaStore.users.findOneBy("login", login) || oktaStore.users.findOneBy("email", email)) {
      return oktaError(c, 400, "E0000001", "A user with the same login or email already exists");
    }

    const activate = boolFromQuery(c.req.query("activate"), true);
    const now = nowIso();
    const firstName = typeof profile.firstName === "string" ? profile.firstName : "Test";
    const lastName = typeof profile.lastName === "string" ? profile.lastName : "User";
    const displayName =
      typeof profile.displayName === "string" ? profile.displayName : `${firstName} ${lastName}`.trim() || login;

    const created = oktaStore.users.insert({
      okta_id: generateOktaId("00u"),
      status: activate ? "ACTIVE" : "STAGED",
      activated_at: activate ? now : null,
      status_changed_at: now,
      last_login_at: null,
      password_changed_at: null,
      transitioning_to_status: null,
      login,
      email,
      first_name: firstName,
      last_name: lastName,
      display_name: displayName,
      locale: typeof profile.locale === "string" ? profile.locale : "en-US",
      time_zone: typeof profile.timeZone === "string" ? profile.timeZone : "UTC",
    });

    recordManagementEvent(store, c, auth, "user.lifecycle.create", [userEntity(created)]);
    if (activate) recordManagementEvent(store, c, auth, "user.lifecycle.activate", [userEntity(created)]);
    return c.json(userResponse(baseUrl, created), 201);
  });

  app.get("/api/v1/users/me", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = oktaStore.users.findOneBy("login", auth.login) ?? oktaStore.users.all()[0];
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");

    const response = userResponse(baseUrl, user);
    return c.json({
      ...response,
      profile: {
        ...(response.profile as Record<string, unknown>),
        displayName: userDisplayName(user),
      },
    });
  });

  app.get("/api/v1/users/:userId/groups", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;

    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");

    const memberships = oktaStore.groupMemberships.findBy("user_okta_id", user.okta_id);
    const groups = memberships
      .map((membership) => oktaStore.groups.findOneBy("okta_id", membership.group_okta_id))
      .filter((group): group is NonNullable<typeof group> => Boolean(group));

    return c.json(
      groups.map((group) => ({
        id: group.okta_id,
        profile: {
          name: group.name,
          description: group.description,
        },
        type: group.type,
      })),
    );
  });

  lifecycle("activate", "ACTIVE", "user.lifecycle.activate");

  app.delete("/api/v1/users/:userId/sessions", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");
    if (c.req.query("oauthTokens") === "true") revokeUserOAuthTokens(store, user.okta_id, tokenMap);
    recordManagementEvent(store, c, auth, "user.session.clear", [userEntity(user)]);
    return c.body(null, 204);
  });

  lifecycle("deactivate", "DEPROVISIONED", "user.lifecycle.deactivate");

  lifecycle("suspend", "SUSPENDED", "user.lifecycle.suspend");

  lifecycle("unsuspend", "ACTIVE", "user.lifecycle.unsuspend");

  app.get("/api/v1/users/:userId", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;

    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");
    return c.json(userResponse(baseUrl, user));
  });

  app.put("/api/v1/users/:userId", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;

    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");

    const body = await readJsonObject(c);
    const profile = (body.profile && typeof body.profile === "object" ? body.profile : {}) as Record<string, unknown>;

    const updates = updateUserProfile(user, profile);
    if (
      (updates.login !== user.login && oktaStore.users.findOneBy("login", updates.login ?? "")) ||
      (updates.email !== user.email && oktaStore.users.findOneBy("email", updates.email ?? ""))
    ) {
      return oktaError(c, 400, "E0000001", "A user with the same login or email already exists");
    }

    const updated = oktaStore.users.update(user.id, updates) ?? user;
    recordManagementEvent(store, c, auth, "user.account.update_profile", [userEntity(updated)]);
    return c.json(userResponse(baseUrl, updated));
  });

  app.post("/api/v1/users/:userId", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;

    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");

    const body = await readJsonObject(c);
    const profile = (body.profile && typeof body.profile === "object" ? body.profile : {}) as Record<string, unknown>;
    const updates = updateUserProfile(user, profile);
    const updated = oktaStore.users.update(user.id, updates) ?? user;
    recordManagementEvent(store, c, auth, "user.account.update_profile", [userEntity(updated)]);
    return c.json(userResponse(baseUrl, updated));
  });

  app.delete("/api/v1/users/:userId", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;

    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");

    // Match Okta behavior: first delete request deactivates, second removes.
    if (user.status !== "DEPROVISIONED") {
      const deactivated = oktaStore.users.update(user.id, setLifecycleStatus(user, "DEPROVISIONED")) ?? user;
      revokeUserApiTokens(store, user.okta_id);
      recordManagementEvent(store, c, auth, "user.lifecycle.deactivate", [userEntity(deactivated)]);
      return new Response(null, { status: 204 });
    }

    recordManagementEvent(store, c, auth, "user.lifecycle.delete.initiated", [userEntity(user)]);
    for (const membership of oktaStore.groupMemberships.findBy("user_okta_id", user.okta_id)) {
      const group = oktaStore.groups.findOneBy("okta_id", membership.group_okta_id);
      // Okta logs the removal from each group the user was put in, not from built-in groups such as Everyone.
      if (group && group.type !== "BUILT_IN") {
        recordManagementEvent(store, c, auth, "group.user_membership.remove", [userEntity(user), groupTarget(group)]);
      }
      oktaStore.groupMemberships.delete(membership.id);
    }
    for (const assignment of oktaStore.appAssignments.findBy("user_okta_id", user.okta_id)) {
      oktaStore.appAssignments.delete(assignment.id);
    }
    for (const role of oktaStore.roleAssignments.findBy("user_okta_id", user.okta_id)) {
      oktaStore.roleAssignments.delete(role.id);
    }

    oktaStore.users.delete(user.id);
    // Once the user is gone, its login is no longer known: the target's alternate id is the user id.
    recordManagementEvent(store, c, auth, "user.lifecycle.delete.completed", [
      { ...userEntity(user), alternateId: user.okta_id },
    ]);
    return new Response(null, { status: 204 });
  });

  app.post("/api/v1/users/:userId/lifecycle/reactivate", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");
    const updated =
      oktaStore.users.update(user.id, {
        status: "PROVISIONED",
        status_changed_at: nowIso(),
        transitioning_to_status: null,
      }) ?? user;
    recordManagementEvent(store, c, auth, "user.lifecycle.reactivate", [userEntity(updated)]);
    return c.json(userResponse(baseUrl, updated));
  });
}
