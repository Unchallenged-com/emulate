import type { Context, RouteContext } from "@emulators/core";
import { directoryAuthError, findUserByKey } from "../directory.js";
import type { GoogleGroup } from "../entities.js";
import {
  buildGroupsSettingsDiscoveryDocument,
  GROUP_SETTING_KEYS,
  GROUP_SETTING_VALUES,
} from "../groups-settings-discovery.js";
import { getAuthenticatedEmail, googleApiError } from "../helpers.js";
import { parseGoogleBody } from "../route-helpers.js";
import { getGoogleStore } from "../store.js";

const PATH = "/groups/v1/groups/:groupUniqueId";

// The Groups resource's own limits and rules
// (https://developers.google.com/workspace/admin/groups-settings/v1/reference/groups):
// "Name of the group, which has a maximum size of 75 characters"; a description "no more than 300 characters";
// custom footer text of at most 1,000 characters; a deny notification of at most 10,000.
const MAX_LENGTH: Record<string, number> = {
  name: 75,
  description: 300,
  customFooterText: 1000,
  defaultMessageDenyNotificationText: 10000,
};
// "This field is read-only and update/patch requests to it are ignored" (customRolesEnabledForSettingsToBeMerged);
// the email "can be updated using the Directory API"; kind is the resource type.
const IGNORED = new Set(["kind", "email", "customRolesEnabledForSettingsToBeMerged"]);
// The defaults the reference states: spamModerationLevel MODERATE ("This is the default"), messageDisplayFont
// ("always has a value of DEFAULT_FONT"), whoCanAddReferences ("The value is always NONE").
const DOCUMENTED_DEFAULTS: Record<string, string> = {
  spamModerationLevel: "MODERATE",
  messageDisplayFont: "DEFAULT_FONT",
  whoCanAddReferences: "NONE",
};

const invalid = (c: Context, message: string) => googleApiError(c, 400, message, "invalid", "INVALID_ARGUMENT");

export function settingsResource(group: GoogleGroup): Record<string, unknown> {
  return {
    kind: "groupsSettings#groups",
    email: group.email,
    name: group.name,
    description: group.description,
    ...DOCUMENTED_DEFAULTS,
    ...(group.settings ?? {}),
  };
}

export function groupsSettingsRoutes({ app, store, baseUrl }: RouteContext): void {
  const gs = getGoogleStore(store);

  app.get("/discovery/v1/apis/groupssettings/v1/rest", (c) => c.json(buildGroupsSettingsDiscoveryDocument(baseUrl)));

  function checkCaller(c: Context): Response | undefined {
    const email = getAuthenticatedEmail(c);
    if (!email) return directoryAuthError(c);
    const user = findUserByKey(gs, email);
    if (store.getData<boolean>("google.strict_scopes") === true && (!user || user.is_admin !== true)) {
      return googleApiError(c, 403, "Not Authorized to access this resource/api", "forbidden", "PERMISSION_DENIED");
    }
    // The API answers JSON when asked (alt=json, as client libraries do); its default, Atom, is not modeled.
    if ((c.req.query("alt") ?? "atom") !== "json") {
      return googleApiError(
        c,
        400,
        "Invalid Input: alt=atom is not supported by the emulator",
        "badRequest",
        "INVALID_ARGUMENT",
      );
    }
    return undefined;
  }

  // The group is named by its email address only ("The group's email address", the groupUniqueId parameter; GAM
  // notes that the "group settings API won't take uid").
  function findGroup(c: Context): GoogleGroup | Response {
    const key = (c.req.param("groupUniqueId") ?? "").toLowerCase();
    const group = gs.groups.all().find((g) => g.email.toLowerCase() === key);
    return group ?? googleApiError(c, 404, "Resource Not Found: groupKey", "notFound", "NOT_FOUND");
  }

  app.get(PATH, (c) => {
    const refused = checkCaller(c);
    if (refused) return refused;
    const group = findGroup(c);
    if (group instanceof Response) return group;
    return c.json(settingsResource(group));
  });

  const update = async (c: Context) => {
    const refused = checkCaller(c);
    if (refused) return refused;
    const group = findGroup(c);
    if (group instanceof Response) return group;
    const body = await parseGoogleBody(c);
    const settings: Record<string, string | number> = { ...(group.settings ?? {}) };
    let name = group.name;
    let description = group.description;
    for (const [key, raw] of Object.entries(body)) {
      if (IGNORED.has(key) || raw === undefined || raw === null) continue;
      if (!GROUP_SETTING_KEYS.includes(key)) return invalid(c, "Invalid Value");
      const value = typeof raw === "boolean" ? String(raw) : raw;
      if (key === "maxMessageBytes") {
        if (!/^\d+$/.test(String(value))) return invalid(c, "Invalid Value");
        settings[key] = Number(value);
        continue;
      }
      if (typeof value !== "string") return invalid(c, "Invalid Value");
      const allowed = GROUP_SETTING_VALUES[key];
      if (allowed && !allowed.includes(value)) return invalid(c, "Invalid Value");
      if (MAX_LENGTH[key] !== undefined && value.length > MAX_LENGTH[key]) return invalid(c, "Invalid Value");
      if (key === "name") name = value;
      else if (key === "description") description = value;
      else settings[key] = value;
    }
    // "UPDATE and PATCH requests ignore this field if allowExternalMembers is false."
    if (settings.allowExternalMembers !== "true") {
      const previous = group.settings?.whoCanAddExternalMembers;
      if (previous === undefined) delete settings.whoCanAddExternalMembers;
      else settings.whoCanAddExternalMembers = previous;
    }
    // "When archiveOnly is false, updating whoCanPostMessage to NONE_CAN_POST, results in an error."
    if (settings.whoCanPostMessage === "NONE_CAN_POST" && settings.archiveOnly !== "true") {
      return invalid(c, "Invalid Value");
    }
    // REPLY_TO_CUSTOM: "the customReplyTo property holds a custom email address ... Otherwise an error is returned."
    if (settings.replyTo === "REPLY_TO_CUSTOM" && !settings.customReplyTo) return invalid(c, "Invalid Value");

    const updated = gs.groups.update(group.id, { name, description, settings }) ?? group;
    return c.json(settingsResource(updated));
  };
  app.put(PATH, update);
  app.patch(PATH, update);
}
