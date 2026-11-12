import type { Context, RouteContext } from "@emulators/core";
import { buildDirectoryDiscoveryDocument } from "../directory-discovery.js";
import {
  directoryUsers,
  emailDomain,
  findGroupByKey,
  findMember,
  findUserByKey,
  generateDirectoryUserId,
  generateGroupId,
  getCustomerId,
  groupContains,
  groupResource,
  memberResource,
  parseFieldSelector,
  removeMemberships,
  selectFields,
  userResource,
} from "../directory.js";
import type { GoogleGroup, GoogleGroupMember, GoogleUser } from "../entities.js";
import { getAuthenticatedEmail, googleApiError } from "../helpers.js";
import { parseGoogleBody } from "../route-helpers.js";
import { getGoogleStore } from "../store.js";

const PREFIX = "/admin/directory/v1";
const ROLES = ["OWNER", "MANAGER", "MEMBER"] as const;

// Reasons and statuses of Google's global error domain
// (https://developers.google.com/youtube/v3/docs/core_errors); the messages are the emulator's own.
const badRequest = (c: Context, message: string) => googleApiError(c, 400, message, "badRequest", "INVALID_ARGUMENT");
const invalid = (c: Context, message: string) => googleApiError(c, 400, message, "invalid", "INVALID_ARGUMENT");
const required = (c: Context, message: string) => googleApiError(c, 400, message, "required", "INVALID_ARGUMENT");
const notFound = (c: Context, message: string) => googleApiError(c, 404, message, "notFound", "NOT_FOUND");
const duplicate = (c: Context, message: string) => googleApiError(c, 409, message, "duplicate", "ALREADY_EXISTS");

function json(c: Context, body: unknown): Response {
  return c.json(selectFields(body, parseFieldSelector(c.req.query("fields") ?? "")));
}

// "A successful response returns an HTTP 200 status code."
// (https://developers.google.com/workspace/admin/directory/v1/guides/manage-users#delete_user)
function empty(c: Context): Response {
  return c.body(null, 200);
}

function page<T>(c: Context, items: T[], defaultMax: number, max: number): { items: T[]; nextPageToken?: string } {
  const requested = Number.parseInt(c.req.query("maxResults") ?? "", 10);
  const size = Number.isFinite(requested) && requested > 0 ? Math.min(requested, max) : defaultMax;
  const offset = Number.parseInt(Buffer.from(c.req.query("pageToken") ?? "", "base64url").toString() || "0", 10) || 0;
  const slice = items.slice(offset, offset + size);
  const next = offset + size < items.length ? Buffer.from(String(offset + size)).toString("base64url") : undefined;
  return { items: slice, ...(next ? { nextPageToken: next } : {}) };
}

function bool(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (value === "true") return true;
  if (value === "false") return false;
  return undefined;
}

function str(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

// Password rules of users.insert and the User resource's `hashFunction`
// (https://developers.google.com/workspace/admin/directory/v1/guides/manage-users#create_user).
function passwordProblem(password: string, hashFunction: string | undefined): string | null {
  if (hashFunction === undefined) {
    return /^[\x20-\x7e]{8,100}$/.test(password) ? null : "Invalid Password";
  }
  if (hashFunction === "MD5") return /^[0-9a-fA-F]{32}$/.test(password) ? null : "Invalid Password";
  if (hashFunction === "SHA-1") return /^[0-9a-fA-F]{40}$/.test(password) ? null : "Invalid Password";
  if (hashFunction === "crypt") {
    const rounds = /^\$[56]\$rounds=(\d+)\$/.exec(password);
    if (rounds && Number(rounds[1]) > 10000) return "Invalid Password";
    return /^(\$1\$|\$5\$|\$6\$)/.test(password) || /^[./0-9A-Za-z]{13}$/.test(password) ? null : "Invalid Password";
  }
  return "Invalid Input: hashFunction";
}

export function adminDirectoryRoutes({ app, store, baseUrl }: RouteContext): void {
  const gs = getGoogleStore(store);

  const discovery = (c: Context) => c.json(buildDirectoryDiscoveryDocument(baseUrl));
  app.get("/discovery/v1/apis/admin/directory_v1/rest", discovery);
  app.get("/$discovery/rest", (c) => {
    if (c.req.query("version") !== "directory_v1") return notFound(c, "Discovery document not found.");
    return discovery(c);
  });

  /**
   * The caller, who must be a super administrator in strict mode: the Directory API is an administrator API
   * (https://developers.google.com/workspace/admin/directory/v1/guides/authorizing), and users.makeAdmin can only be
   * performed by "an account's super administrator". Delegated administrator roles are not modeled.
   */
  function requireAdmin(c: Context): GoogleUser | Response {
    const email = getAuthenticatedEmail(c);
    const user = email ? findUserByKey(gs, email) : undefined;
    if (!email) {
      return googleApiError(c, 401, "Request had invalid authentication credentials.", "authError", "UNAUTHENTICATED");
    }
    if (store.getData<boolean>("google.strict_scopes") === true && (!user || user.is_admin !== true)) {
      return googleApiError(c, 403, "Not Authorized to access this resource/api", "forbidden", "PERMISSION_DENIED");
    }
    return user ?? ({ email } as GoogleUser);
  }

  function customerScope(c: Context): ((email: string) => boolean) | Response {
    const customer = c.req.query("customer");
    const domain = c.req.query("domain")?.toLowerCase();
    if (!customer && !domain) return badRequest(c, "Bad Request");
    if (customer && customer !== "my_customer" && customer !== getCustomerId(store)) {
      return badRequest(c, "Bad Request");
    }
    if (domain) {
      const known = directoryUsers(gs).some((user) => emailDomain(user.email) === domain);
      if (!known) return badRequest(c, "Bad Request");
      return (email) => emailDomain(email) === domain;
    }
    return () => true;
  }

  function addressTaken(email: string, except?: { uid?: string; group?: string }): boolean {
    const user = findUserByKey(gs, email);
    const group = findGroupByKey(gs, email);
    return Boolean((user && user.uid !== except?.uid) || (group && group.google_id !== except?.group));
  }

  // ---------- Users ----------

  app.get(`${PREFIX}/users`, (c) => {
    const admin = requireAdmin(c);
    if (admin instanceof Response) return admin;
    if (c.req.query("query") !== undefined) return badRequest(c, "Invalid Input: query is not supported");
    const inScope = customerScope(c);
    if (inScope instanceof Response) return inScope;
    const orderBy = c.req.query("orderBy") ?? "email";
    const key = (user: GoogleUser) =>
      (orderBy === "givenName"
        ? user.given_name
        : orderBy === "familyName"
          ? user.family_name
          : user.email
      ).toLowerCase();
    const users = directoryUsers(gs)
      .filter((user) => inScope(user.email))
      .sort((a, b) => key(a).localeCompare(key(b)));
    if (c.req.query("sortOrder") === "DESCENDING") users.reverse();
    const result = page(c, users, 100, 500);
    return json(c, {
      kind: "admin#directory#users",
      users: result.items.map((user) => userResource(store, user)),
      ...(result.nextPageToken ? { nextPageToken: result.nextPageToken } : {}),
    });
  });

  app.get(`${PREFIX}/users/:userKey`, (c) => {
    const admin = requireAdmin(c);
    if (admin instanceof Response) return admin;
    const user = findUserByKey(gs, c.req.param("userKey") ?? "");
    if (!user) return notFound(c, "Resource Not Found: userKey");
    return json(c, userResource(store, user));
  });

  app.post(`${PREFIX}/users`, async (c) => {
    const admin = requireAdmin(c);
    if (admin instanceof Response) return admin;
    const body = await parseGoogleBody(c);
    const primaryEmail = str(body.primaryEmail)?.trim();
    const name = (body.name && typeof body.name === "object" ? body.name : {}) as Record<string, unknown>;
    const givenName = str(name.givenName)?.trim();
    const familyName = str(name.familyName)?.trim();
    const password = str(body.password);
    if (!primaryEmail) return required(c, "Invalid Input: primary_user_email");
    if (!givenName) return required(c, "Invalid Given/Family Name: GivenName");
    if (!familyName) return required(c, "Invalid Given/Family Name: FamilyName");
    if (password === undefined) return required(c, "Invalid Password");
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(primaryEmail)) return invalid(c, "Invalid Input: primary_user_email");
    if (givenName.length > 60 || familyName.length > 60) return invalid(c, "Invalid Given/Family Name");
    const problem = passwordProblem(password, str(body.hashFunction));
    if (problem) return invalid(c, problem);
    if (addressTaken(primaryEmail)) return duplicate(c, "Entity already exists.");

    const now = new Date().toISOString();
    const suspended = bool(body.suspended) === true;
    const user = gs.users.insert({
      uid: generateDirectoryUserId(),
      email: primaryEmail,
      name: `${givenName} ${familyName}`,
      given_name: givenName,
      family_name: familyName,
      picture: null,
      email_verified: true,
      locale: "en",
      hd: emailDomain(primaryEmail),
      is_admin: false,
      suspended,
      suspension_time: suspended ? now : null,
      org_unit_path: str(body.orgUnitPath) ?? "/",
      change_password_at_next_login: bool(body.changePasswordAtNextLogin) === true,
      include_in_global_address_list: bool(body.includeInGlobalAddressList) ?? true,
      creation_time: now,
      last_login_time: null,
    });
    return json(c, userResource(store, user));
  });

  const updateUser = async (c: Context) => {
    const admin = requireAdmin(c);
    if (admin instanceof Response) return admin;
    const user = findUserByKey(gs, c.req.param("userKey") ?? "");
    if (!user) return notFound(c, "Resource Not Found: userKey");
    const body = await parseGoogleBody(c);
    const changes: Partial<GoogleUser> = {};

    const primaryEmail = str(body.primaryEmail)?.trim();
    if (primaryEmail !== undefined && primaryEmail.toLowerCase() !== user.email.toLowerCase()) {
      return badRequest(c, "Renaming a user is not supported by the emulator");
    }
    if (body.name && typeof body.name === "object") {
      const name = body.name as Record<string, unknown>;
      const givenName = str(name.givenName)?.trim() ?? user.given_name;
      const familyName = str(name.familyName)?.trim() ?? user.family_name;
      if (!givenName || !familyName || givenName.length > 60 || familyName.length > 60) {
        return invalid(c, "Invalid Given/Family Name");
      }
      Object.assign(changes, { given_name: givenName, family_name: familyName, name: `${givenName} ${familyName}` });
    }
    const password = str(body.password);
    if (password !== undefined) {
      const problem = passwordProblem(password, str(body.hashFunction));
      if (problem) return invalid(c, problem);
    }
    const suspended = bool(body.suspended);
    if (suspended !== undefined && suspended !== (user.suspended === true)) {
      changes.suspended = suspended;
      changes.suspension_time = suspended ? new Date().toISOString() : null;
    }
    const orgUnitPath = str(body.orgUnitPath);
    if (orgUnitPath !== undefined) changes.org_unit_path = orgUnitPath;
    const changePassword = bool(body.changePasswordAtNextLogin);
    if (changePassword !== undefined) changes.change_password_at_next_login = changePassword;
    const gal = bool(body.includeInGlobalAddressList);
    if (gal !== undefined) changes.include_in_global_address_list = gal;

    const updated = gs.users.update(user.id, changes) ?? user;
    return json(c, userResource(store, updated));
  };
  app.put(`${PREFIX}/users/:userKey`, updateUser);
  app.patch(`${PREFIX}/users/:userKey`, updateUser);

  app.delete(`${PREFIX}/users/:userKey`, (c) => {
    const admin = requireAdmin(c);
    if (admin instanceof Response) return admin;
    const user = findUserByKey(gs, c.req.param("userKey") ?? "");
    if (!user) return notFound(c, "Resource Not Found: userKey");
    removeMemberships(store, user.uid);
    gs.users.delete(user.id);
    return empty(c);
  });

  // ---------- Groups ----------

  app.get(`${PREFIX}/groups`, (c) => {
    const admin = requireAdmin(c);
    if (admin instanceof Response) return admin;
    if (c.req.query("query") !== undefined) return badRequest(c, "Invalid Input: query is not supported");
    let groups = gs.groups.all();
    const userKey = c.req.query("userKey");
    if (userKey) {
      const user = findUserByKey(gs, userKey);
      const memberId = user?.uid ?? findGroupByKey(gs, userKey)?.google_id;
      if (!memberId) return notFound(c, "Resource Not Found: userKey");
      const groupIds = new Set(gs.groupMembers.findBy("member_id", memberId).map((m) => m.group_google_id));
      groups = groups.filter((group) => groupIds.has(group.google_id));
    } else {
      const inScope = customerScope(c);
      if (inScope instanceof Response) return inScope;
      groups = groups.filter((group) => inScope(group.email));
    }
    groups.sort((a, b) => a.email.toLowerCase().localeCompare(b.email.toLowerCase()));
    if (c.req.query("sortOrder") === "DESCENDING") groups.reverse();
    const result = page(c, groups, 200, 200);
    return json(c, {
      kind: "admin#directory#groups",
      groups: result.items.map((group) => groupResource(gs, group)),
      ...(result.nextPageToken ? { nextPageToken: result.nextPageToken } : {}),
    });
  });

  app.get(`${PREFIX}/groups/:groupKey`, (c) => {
    const admin = requireAdmin(c);
    if (admin instanceof Response) return admin;
    const group = findGroupByKey(gs, c.req.param("groupKey") ?? "");
    if (!group) return notFound(c, "Resource Not Found: groupKey");
    return json(c, groupResource(gs, group));
  });

  app.post(`${PREFIX}/groups`, async (c) => {
    const admin = requireAdmin(c);
    if (admin instanceof Response) return admin;
    const body = await parseGoogleBody(c);
    const email = str(body.email)?.trim();
    if (!email) return required(c, "Missing required field: email");
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return invalid(c, "Invalid Input: email");
    const description = str(body.description) ?? "";
    if (description.length > 4096) return invalid(c, "Invalid Input: description");
    if (addressTaken(email)) return duplicate(c, "Entity already exists.");
    const group = gs.groups.insert({
      google_id: generateGroupId(),
      email,
      name: str(body.name) ?? "",
      description,
      admin_created: true,
    });
    return json(c, groupResource(gs, group));
  });

  const updateGroup = async (c: Context) => {
    const admin = requireAdmin(c);
    if (admin instanceof Response) return admin;
    const group = findGroupByKey(gs, c.req.param("groupKey") ?? "");
    if (!group) return notFound(c, "Resource Not Found: groupKey");
    const body = await parseGoogleBody(c);
    const email = str(body.email)?.trim();
    if (email !== undefined && email.toLowerCase() !== group.email.toLowerCase()) {
      return badRequest(c, "Renaming a group is not supported by the emulator");
    }
    const changes: Partial<GoogleGroup> = {};
    const name = str(body.name);
    if (name !== undefined) changes.name = name;
    const description = str(body.description);
    if (description !== undefined) {
      if (description.length > 4096) return invalid(c, "Invalid Input: description");
      changes.description = description;
    }
    const updated = gs.groups.update(group.id, changes) ?? group;
    return json(c, groupResource(gs, updated));
  };
  app.put(`${PREFIX}/groups/:groupKey`, updateGroup);
  app.patch(`${PREFIX}/groups/:groupKey`, updateGroup);

  app.delete(`${PREFIX}/groups/:groupKey`, (c) => {
    const admin = requireAdmin(c);
    if (admin instanceof Response) return admin;
    const group = findGroupByKey(gs, c.req.param("groupKey") ?? "");
    if (!group) return notFound(c, "Resource Not Found: groupKey");
    removeMemberships(store, group.google_id);
    gs.groups.delete(group.id);
    return empty(c);
  });

  // ---------- Members ----------

  function withGroup(c: Context): GoogleGroup | Response {
    const admin = requireAdmin(c);
    if (admin instanceof Response) return admin;
    const group = findGroupByKey(gs, c.req.param("groupKey") ?? "");
    return group ?? notFound(c, "Resource Not Found: groupKey");
  }

  function membersOf(group: GoogleGroup, derived: boolean): GoogleGroupMember[] {
    const direct = gs.groupMembers.findBy("group_google_id", group.google_id);
    if (!derived) return direct;
    const users = new Map<string, GoogleGroupMember>();
    const seen = new Set<string>([group.google_id]);
    const pending = [...direct];
    while (pending.length > 0) {
      const member = pending.shift()!;
      if (member.type !== "GROUP") {
        if (!users.has(member.member_id)) users.set(member.member_id, member);
      } else if (!seen.has(member.member_id)) {
        seen.add(member.member_id);
        pending.push(...gs.groupMembers.findBy("group_google_id", member.member_id));
      }
    }
    return [...users.values()];
  }

  app.get(`${PREFIX}/groups/:groupKey/members`, (c) => {
    const group = withGroup(c);
    if (group instanceof Response) return group;
    const roles = (c.req.query("roles") ?? "")
      .split(",")
      .map((role) => role.trim().toUpperCase())
      .filter(Boolean);
    const members = membersOf(group, c.req.query("includeDerivedMembership") === "true")
      .filter((member) => roles.length === 0 || roles.includes(member.role))
      .sort((a, b) => a.email.toLowerCase().localeCompare(b.email.toLowerCase()));
    const result = page(c, members, 200, 200);
    return json(c, {
      kind: "admin#directory#members",
      members: result.items.map(memberResource),
      ...(result.nextPageToken ? { nextPageToken: result.nextPageToken } : {}),
    });
  });

  app.get(`${PREFIX}/groups/:groupKey/members/:memberKey`, (c) => {
    const group = withGroup(c);
    if (group instanceof Response) return group;
    const member = findMember(gs, group, c.req.param("memberKey") ?? "");
    if (!member) return notFound(c, "Resource Not Found: memberKey");
    return json(c, memberResource(member));
  });

  app.get(`${PREFIX}/groups/:groupKey/hasMember/:memberKey`, (c) => {
    const group = withGroup(c);
    if (group instanceof Response) return group;
    const key = c.req.param("memberKey") ?? "";
    const memberId = findUserByKey(gs, key)?.uid ?? findGroupByKey(gs, key)?.google_id;
    if (!memberId) return notFound(c, "Resource Not Found: memberKey");
    const direct = gs.groupMembers.findBy("group_google_id", group.google_id).some((m) => m.member_id === memberId);
    const nested = !direct && membersOf(group, true).some((m) => m.member_id === memberId);
    return json(c, { isMember: direct || nested });
  });

  app.post(`${PREFIX}/groups/:groupKey/members`, async (c) => {
    const group = withGroup(c);
    if (group instanceof Response) return group;
    const body = await parseGoogleBody(c);
    const email = str(body.email)?.trim();
    const id = str(body.id)?.trim();
    if (!email && !id) return required(c, "Missing required field: memberKey");
    const role = (str(body.role) ?? "MEMBER").toUpperCase();
    if (!(ROLES as readonly string[]).includes(role)) return invalid(c, "Invalid Input: role");

    const key = (email ?? id)!;
    const user = findUserByKey(gs, key);
    const memberGroup = user ? undefined : findGroupByKey(gs, key);
    if (!user && !memberGroup && !email) return notFound(c, "Resource Not Found: memberKey");
    if (memberGroup && (memberGroup.google_id === group.google_id || groupContains(gs, memberGroup, group))) {
      return invalid(c, "Invalid Input: cyclic memberships not allowed");
    }
    const memberId = user?.uid ?? memberGroup?.google_id ?? key.toLowerCase();
    if (findMember(gs, group, memberId)) return duplicate(c, "Member already exists.");

    const member = gs.groupMembers.insert({
      group_google_id: group.google_id,
      member_id: memberId,
      email: user?.email ?? memberGroup?.email ?? key,
      role: role as GoogleGroupMember["role"],
      type: user ? "USER" : memberGroup ? "GROUP" : "EXTERNAL",
      delivery_settings: str(body.delivery_settings) ?? "ALL_MAIL",
    });
    return json(c, memberResource(member));
  });

  const updateMember = async (c: Context) => {
    const group = withGroup(c);
    if (group instanceof Response) return group;
    const member = findMember(gs, group, c.req.param("memberKey") ?? "");
    if (!member) return notFound(c, "Resource Not Found: memberKey");
    const body = await parseGoogleBody(c);
    const changes: Partial<GoogleGroupMember> = {};
    const role = str(body.role)?.toUpperCase();
    if (role !== undefined) {
      if (!(ROLES as readonly string[]).includes(role)) return invalid(c, "Invalid Input: role");
      changes.role = role as GoogleGroupMember["role"];
    }
    const delivery = str(body.delivery_settings);
    if (delivery !== undefined) changes.delivery_settings = delivery;
    const updated = gs.groupMembers.update(member.id, changes) ?? member;
    return json(c, memberResource(updated));
  };
  app.put(`${PREFIX}/groups/:groupKey/members/:memberKey`, updateMember);
  app.patch(`${PREFIX}/groups/:groupKey/members/:memberKey`, updateMember);

  app.delete(`${PREFIX}/groups/:groupKey/members/:memberKey`, (c) => {
    const group = withGroup(c);
    if (group instanceof Response) return group;
    const member = findMember(gs, group, c.req.param("memberKey") ?? "");
    if (!member) return notFound(c, "Resource Not Found: memberKey");
    gs.groupMembers.delete(member.id);
    return empty(c);
  });
}
