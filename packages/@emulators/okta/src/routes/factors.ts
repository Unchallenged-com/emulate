import type { RouteContext } from "@emulators/core";
import { newTotpSecret, verifyTotp } from "../credentials.js";
import type { OktaFactor, OktaUser } from "../entities.js";
import { generateOktaId } from "../helpers.js";
import { findUserByRef, oktaError, readJsonObject, requireManagementAuth } from "../route-helpers.js";
import { getOktaStore } from "../store.js";
import { recordManagementEvent, userEntity } from "../system-log.js";

// The Factors API for `token:software:totp` factors (Google Authenticator and Okta Verify codes):
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserFactor/

const TOTP = "token:software:totp";
const TOTP_PROVIDERS = new Set(["GOOGLE", "OKTA"]);

// The factor names Okta writes in the outcome reason of factor events ("User set up SOFT_TOKEN factor"): Okta Verify
// codes are OKTA_SOFT_TOKEN, other authenticator apps SOFT_TOKEN.
function factorName(factor: OktaFactor): string {
  return factor.provider === "OKTA" ? "OKTA_SOFT_TOKEN" : "SOFT_TOKEN";
}

export function factorResponse(baseUrl: string, user: OktaUser, factor: OktaFactor): Record<string, unknown> {
  const userHref = `${baseUrl}/api/v1/users/${encodeURIComponent(user.okta_id)}`;
  const selfHref = `${userHref}/factors/${encodeURIComponent(factor.factor_id)}`;
  const links: Record<string, unknown> =
    factor.status === "ACTIVE"
      ? {
          verify: { href: `${selfHref}/verify`, hints: { allow: ["POST"] } },
          self: { href: selfHref, hints: { allow: ["GET", "DELETE"] } },
        }
      : {
          activate: { href: `${selfHref}/lifecycle/activate`, hints: { allow: ["POST"] } },
          self: { href: selfHref, hints: { allow: ["GET"] } },
        };
  links.user = { href: userHref, hints: { allow: ["GET"] } };
  return {
    id: factor.factor_id,
    factorType: factor.factor_type,
    provider: factor.provider,
    vendorName: factor.provider,
    status: factor.status,
    created: factor.created_at,
    lastUpdated: factor.updated_at,
    profile: { credentialId: user.login },
    _links: links,
  };
}

export function factorRoutes({ app, store, baseUrl, tokenMap }: RouteContext): void {
  const oktaStore = getOktaStore(store);

  const findFactor = (user: OktaUser, factorId: string) =>
    oktaStore.factors.findBy("user_okta_id", user.okta_id).find((factor) => factor.factor_id === factorId);

  app.get("/api/v1/users/:userId/factors", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");
    return c.json(
      oktaStore.factors.findBy("user_okta_id", user.okta_id).map((factor) => factorResponse(baseUrl, user, factor)),
    );
  });

  app.post("/api/v1/users/:userId/factors", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");

    const body = await readJsonObject(c);
    const factorType = typeof body.factorType === "string" ? body.factorType : "";
    const provider = typeof body.provider === "string" ? body.provider : "";
    if (factorType !== TOTP || !TOTP_PROVIDERS.has(provider)) {
      return oktaError(c, 400, "E0000001", "Api validation failed: factorType", [
        { errorSummary: "factorType: the emulator enrolls token:software:totp factors from GOOGLE or OKTA" },
      ]);
    }
    const enrolled = oktaStore.factors
      .findBy("user_okta_id", user.okta_id)
      .some((factor) => factor.factor_type === factorType && factor.provider === provider);
    if (enrolled) {
      return oktaError(c, 400, "E0000001", "Api validation failed: factorEnrollRequest", [
        { errorSummary: "A factor of this type is already set up." },
      ]);
    }

    const factor = oktaStore.factors.insert({
      factor_id: generateOktaId("ost"),
      user_okta_id: user.okta_id,
      factor_type: factorType,
      provider,
      status: "PENDING_ACTIVATION",
      shared_secret: newTotpSecret(),
    });
    return c.json({
      ...factorResponse(baseUrl, user, factor),
      _embedded: {
        activation: { timeStep: 30, sharedSecret: factor.shared_secret, encoding: "base32", keyLength: 16 },
      },
    });
  });

  app.get("/api/v1/users/:userId/factors/:factorId", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");
    const factor = findFactor(user, c.req.param("factorId"));
    if (!factor) return oktaError(c, 404, "E0000007", "Not found: factor");
    return c.json(factorResponse(baseUrl, user, factor));
  });

  app.post("/api/v1/users/:userId/factors/:factorId/lifecycle/activate", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");
    const factor = findFactor(user, c.req.param("factorId"));
    if (!factor) return oktaError(c, 404, "E0000007", "Not found: factor");

    const body = await readJsonObject(c);
    const passCode = typeof body.passCode === "string" ? body.passCode : "";
    if (factor.status === "ACTIVE" || !verifyTotp(factor.shared_secret, passCode)) {
      return oktaError(c, 403, "E0000068", "Invalid Passcode/Answer");
    }
    const activated = oktaStore.factors.update(factor.id, { status: "ACTIVE" }) ?? factor;
    recordManagementEvent(store, c, auth, "user.mfa.factor.activate", [userEntity(user)], undefined, {
      result: "SUCCESS",
      reason: `User set up ${factorName(factor)} factor`,
    });
    return c.json(factorResponse(baseUrl, user, activated));
  });

  app.delete("/api/v1/users/:userId/factors/:factorId", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");
    // "You can't unenroll a factor from a deactivated user."
    if (user.status === "DEPROVISIONED") {
      return oktaError(c, 403, "E0000038", "This operation is not allowed in the user's current status.");
    }
    const factor = findFactor(user, c.req.param("factorId"));
    if (!factor) return oktaError(c, 404, "E0000007", "Not found: factor");

    oktaStore.factors.delete(factor.id);
    recordManagementEvent(store, c, auth, "user.mfa.factor.deactivate", [userEntity(user)], undefined, {
      result: "SUCCESS",
      reason: `User reset ${factorName(factor)} factor`,
    });
    return c.body(null, 204);
  });

  app.post("/api/v1/users/:userId/lifecycle/reset_factors", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(oktaStore, c.req.param("userId"));
    if (!user) return oktaError(c, 404, "E0000007", "Not found: user");
    // Identity Engine records the reset of each factor; user.mfa.factor.reset_all is a Classic Engine event.
    for (const factor of oktaStore.factors.findBy("user_okta_id", user.okta_id)) {
      oktaStore.factors.delete(factor.id);
      recordManagementEvent(store, c, auth, "user.mfa.factor.deactivate", [userEntity(user)], undefined, {
        result: "SUCCESS",
        reason: `User reset ${factorName(factor)} factor`,
      });
    }
    return c.json({});
  });
}
