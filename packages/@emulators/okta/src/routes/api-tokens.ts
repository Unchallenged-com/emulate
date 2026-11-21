import type { RouteContext } from "@emulators/core";
import { apiTokenResponse, findApiToken, revokeApiToken } from "../api-tokens.js";
import { oktaError, requireManagementAuth } from "../route-helpers.js";
import { getOktaStore } from "../store.js";
import { apiTokenTarget, recordManagementEvent } from "../system-log.js";

// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/ApiToken/
export function apiTokenRoutes({ app, store, baseUrl, tokenMap }: RouteContext): void {
  const oktaStore = getOktaStore(store);

  app.get("/api/v1/api-tokens", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    return c.json(oktaStore.apiTokens.all().map((token) => apiTokenResponse(baseUrl, token)));
  });

  // Registered before the `:apiTokenId` routes so that `current` is not read as a token id.
  app.delete("/api/v1/api-tokens/current", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const header = c.req.header("Authorization") ?? "";
    const token = /^ssws\s+/i.test(header) ? findApiToken(store, header.replace(/^ssws\s+/i, "").trim()) : undefined;
    if (token) {
      recordManagementEvent(store, c, auth, "system.api_token.revoke", [apiTokenTarget(token)], {
        networkConnection: "ANYWHERE",
      });
      revokeApiToken(store, token);
    }
    return c.body(null, 204);
  });

  app.get("/api/v1/api-tokens/:apiTokenId", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const token = oktaStore.apiTokens.findOneBy("token_id", c.req.param("apiTokenId"));
    if (!token) return oktaError(c, 404, "E0000007", "Not found: api token");
    return c.json(apiTokenResponse(baseUrl, token));
  });

  app.delete("/api/v1/api-tokens/:apiTokenId", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const token = oktaStore.apiTokens.findOneBy("token_id", c.req.param("apiTokenId"));
    if (!token) return oktaError(c, 404, "E0000007", "Not found: api token");
    recordManagementEvent(store, c, auth, "system.api_token.revoke", [apiTokenTarget(token)], {
      networkConnection: "ANYWHERE",
    });
    revokeApiToken(store, token);
    return c.body(null, 204);
  });
}
