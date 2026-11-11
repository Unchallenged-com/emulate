import { debug } from "@emulators/core";
import type { OktaGroup, OktaUser } from "./entities.js";
import { userDisplayName } from "./helpers.js";
import { SAML_ATTRNAME_FORMATS } from "./saml-constants.js";

export interface SamlAttribute {
  name: string;
  nameFormat: string;
  values: string[];
}

// Okta user profile attributes (`UserProfile` in the Okta Management API) that the emulator stores.
const USER_PROFILE_ATTRIBUTES: Record<string, (user: OktaUser) => string> = {
  login: (user) => user.login,
  email: (user) => user.email,
  firstName: (user) => user.first_name,
  lastName: (user) => user.last_name,
  displayName: (user) => userDisplayName(user),
  locale: (user) => user.locale,
  timezone: (user) => user.time_zone,
};

// Okta Expression Language: "To reference a user profile attribute, specify `user.` and the attribute variable name."
const USER_ATTRIBUTE_EXPRESSION = /^user\.([A-Za-z][A-Za-z0-9_]*)$/;

function evaluateExpression(expression: string, user: OktaUser): string | undefined {
  const match = USER_ATTRIBUTE_EXPRESSION.exec(expression.trim());
  const resolve = match ? USER_PROFILE_ATTRIBUTES[match[1]] : undefined;
  if (!resolve) {
    debug("okta.saml", `[attributes] expression not supported by the emulator, value omitted: ${expression}`);
    return undefined;
  }
  return resolve(user);
}

function groupMatches(filterType: unknown, filterValue: string, groupName: string): boolean {
  switch (filterType) {
    case "STARTS_WITH":
      return groupName.startsWith(filterValue);
    case "EQUALS":
      return groupName === filterValue;
    case "CONTAINS":
      return groupName.includes(filterValue);
    case "REGEX":
      try {
        return new RegExp(`^(?:${filterValue})$`).test(groupName);
      } catch {
        debug("okta.saml", `[attributes] invalid group filter regex, no group matched: ${filterValue}`);
        return false;
      }
    default:
      return false;
  }
}

/**
 * Resolves `settings.signOn.attributeStatements` of a SAML 2.0 app for a user. An attribute without any value
 * (an unsupported expression, or no matching group) is left out of the assertion.
 */
export function resolveAttributeStatements(statements: unknown, user: OktaUser, groups: OktaGroup[]): SamlAttribute[] {
  if (!Array.isArray(statements)) return [];

  const attributes: SamlAttribute[] = [];
  for (const raw of statements) {
    if (!raw || typeof raw !== "object") continue;
    const statement = raw as Record<string, unknown>;
    const name = typeof statement.name === "string" ? statement.name : "";
    if (!name) continue;
    // "Basic: A simple string. This is the default format."
    const nameFormat =
      typeof statement.namespace === "string" && statement.namespace
        ? statement.namespace
        : SAML_ATTRNAME_FORMATS.basic;

    let values: string[] = [];
    if (statement.type === "EXPRESSION" && Array.isArray(statement.values)) {
      values = statement.values
        .filter((value): value is string => typeof value === "string")
        .map((value) => evaluateExpression(value, user))
        .filter((value): value is string => value !== undefined);
    } else if (statement.type === "GROUP" && typeof statement.filterValue === "string") {
      const filterValue = statement.filterValue;
      values = groups
        .map((group) => group.name)
        .filter((groupName) => groupMatches(statement.filterType, filterValue, groupName));
    }

    if (values.length > 0) attributes.push({ name, nameFormat, values });
  }
  return attributes;
}
