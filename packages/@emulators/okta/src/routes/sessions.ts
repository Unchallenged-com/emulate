import type { AppEnv, Context, RouteContext, Store } from "@emulators/core";
import type { OktaSession } from "../entities.js";
import { oktaError, requireManagementAuth } from "../route-helpers.js";
import { endSession, isSessionActive, sessionResponse, touchSession } from "../sessions.js";
import { getOktaStore } from "../store.js";
import { recordManagementEvent, userEntity } from "../system-log.js";

// The Sessions API's session operations: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Session/

/**
 * Ends a session an administrator revokes, recorded as user.session.end on the user ("a separate user.session.end
 * ... for each of the user's active sessions"). Recorded session ends carry the request's debug data only.
 */
export function revokeSession(store: Store, c: Context<AppEnv>, auth: { login: string }, session: OktaSession): void {
  const user = getOktaStore(store).users.findOneBy("okta_id", session.user_okta_id);
  endSession(store, session);
  if (user) recordManagementEvent(store, c, auth, "user.session.end", [userEntity(user)]);
}

export function sessionRoutes({ app, store, baseUrl, tokenMap }: RouteContext): void {
  const oktaStore = getOktaStore(store);

  const sessionOf = (c: Context<AppEnv>) => {
    const session = oktaStore.sessions.findOneBy("session_id", c.req.param("sessionId"));
    return session && isSessionActive(session) ? session : undefined;
  };
  const notFound = (c: Context<AppEnv>) =>
    oktaError(c, 404, "E0000007", `Not found: Resource not found: ${c.req.param("sessionId")} (Session)`);
  const respond = (c: Context<AppEnv>, session: OktaSession) => {
    const user = oktaStore.users.findOneBy("okta_id", session.user_okta_id);
    if (!user) return notFound(c);
    return c.json(sessionResponse(store, baseUrl, session, user));
  };

  app.get("/api/v1/sessions/:sessionId", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const session = sessionOf(c);
    if (!session) return notFound(c);
    return respond(c, session);
  });

  app.post("/api/v1/sessions/:sessionId/lifecycle/refresh", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const session = sessionOf(c);
    if (!session) return notFound(c);
    // "A successful response contains the refreshed session with an updated expiresAt timestamp."
    return respond(c, touchSession(store, session));
  });

  app.delete("/api/v1/sessions/:sessionId", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const session = sessionOf(c);
    if (!session) return notFound(c);
    revokeSession(store, c, auth, session);
    return c.body(null, 204);
  });
}
