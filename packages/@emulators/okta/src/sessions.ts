import type { AppEnv, Context, Store } from "@emulators/core";
import type { OktaSession, OktaUser } from "./entities.js";
import { generateOktaId } from "./helpers.js";
import { getOktaStore } from "./store.js";
import { sessionId } from "./system-log.js";

// Okta sessions: a sign-in opens one, kept in the `idx` cookie, and the Sessions API reads, refreshes and revokes it
// (https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Session/).

/** Identity Engine keeps the session in the `idx` cookie ("The new idx cookie is used"). */
export const SESSION_COOKIE = "idx";

// The global session policy defaults: maxSessionIdleMinutes 120, and maxSessionLifetimeMinutes 1440 for the default
// rule (release 2025.03.0).
const IDLE_MS = 120 * 60 * 1000;
const LIFETIME_MS = 1440 * 60 * 1000;

const ORG_ID_KEY = "okta.org_id";

/** The org's id, which a session's `idp.id` carries when Okta authenticated the user. */
function orgId(store: Store): string {
  let id = store.getData<string>(ORG_ID_KEY);
  if (!id) {
    id = generateOktaId("00o");
    store.setData(ORG_ID_KEY, id);
  }
  return id;
}

export function sessionExpiresAt(session: OktaSession): string {
  const idle = Date.parse(session.last_activity_at) + IDLE_MS;
  const lifetime = Date.parse(session.created_at) + LIFETIME_MS;
  return new Date(Math.min(idle, lifetime)).toISOString();
}

export function isSessionActive(session: OktaSession): boolean {
  return Date.parse(sessionExpiresAt(session)) > Date.now();
}

export function openSession(store: Store, c: Context<AppEnv>, user: OktaUser): OktaSession {
  const now = new Date().toISOString();
  const session = getOktaStore(store).sessions.insert({
    session_id: sessionId("idx"),
    user_okta_id: user.okta_id,
    last_activity_at: now,
    authenticated_at: now,
  });
  // HttpOnly, Secure and SameSite=None, as Okta sets its session cookies.
  c.header("Set-Cookie", `${SESSION_COOKIE}=${session.session_id}; Path=/; HttpOnly; Secure; SameSite=None`, {
    append: true,
  });
  return session;
}

/** The active session of the request's cookie, if any; ended or expired sessions are dropped. */
export function cookieSession(store: Store, c: Context<AppEnv>): OktaSession | undefined {
  const cookie = c.req.header("Cookie") ?? "";
  const value = cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${SESSION_COOKIE}=`))
    ?.slice(SESSION_COOKIE.length + 1);
  if (!value) return undefined;
  const session = getOktaStore(store).sessions.findOneBy("session_id", value);
  if (!session) return undefined;
  if (!isSessionActive(session)) {
    getOktaStore(store).sessions.delete(session.id);
    return undefined;
  }
  return session;
}

/** Records the session's use, which moves its idle expiry. */
export function touchSession(store: Store, session: OktaSession): OktaSession {
  return getOktaStore(store).sessions.update(session.id, { last_activity_at: new Date().toISOString() }) ?? session;
}

export function endSession(store: Store, session: OktaSession): void {
  getOktaStore(store).sessions.delete(session.id);
}

export function clearSessionCookie(c: Context<AppEnv>): void {
  c.header("Set-Cookie", `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0`, { append: true });
}

export function userSessions(store: Store, userOktaId: string): OktaSession[] {
  return getOktaStore(store)
    .sessions.findBy("user_okta_id", userOktaId)
    .filter((session) => isSessionActive(session));
}

export function sessionResponse(store: Store, baseUrl: string, session: OktaSession, user: OktaUser) {
  return {
    amr: ["pwd"],
    createdAt: session.created_at,
    expiresAt: sessionExpiresAt(session),
    id: session.session_id,
    idp: { id: orgId(store), type: "OKTA" },
    lastPasswordVerification: session.authenticated_at,
    login: user.login,
    status: "ACTIVE",
    userId: user.okta_id,
    _links: {
      self: {
        href: `${baseUrl}/api/v1/sessions/${encodeURIComponent(session.session_id)}`,
        hints: { allow: ["DELETE"] },
      },
    },
  };
}
