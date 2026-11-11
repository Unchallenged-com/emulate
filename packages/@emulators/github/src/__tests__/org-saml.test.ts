import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { DOMParser } from "@xmldom/xmldom";
import { createServer, type AppKeyResolver, type Hono, type Store } from "@emulators/core";
import { createAppKeyResolver, getGitHubStore, githubPlugin, seedFromConfig } from "../index.js";
import { getActiveSamlSession, getLinkedSamlIdentity } from "../saml.js";
import {
  base,
  idpUrl,
  idpIssuer,
  entityId,
  acsUrl,
  SAMLP_NS,
  SAML_NS,
  idpKey,
  otherKey,
  signIn,
  hiddenField,
  startSso,
  buildResponse,
  consume,
} from "./saml-fixtures.js";

function createTestApp(saml?: { issuer?: string }) {
  // Built the way the CLI builds it: an App key resolver over the store, and a fallback user.
  const keys: { resolve?: AppKeyResolver } = {};
  const { app, store } = createServer(githubPlugin, {
    baseUrl: base,
    appKeyResolver: (appId) => keys.resolve!(appId),
    fallbackUser: { login: "octocat", id: 1, scopes: ["repo", "user", "admin:org", "admin:repo_hook"] },
  });
  keys.resolve = createAppKeyResolver(store);
  githubPlugin.seed?.(store, base);
  seedFromConfig(store, base, {
    users: [{ login: "octocat" }, { login: "hubot" }],
    orgs: [
      {
        login: "acme",
        members: [{ login: "octocat" }, { login: "hubot" }],
        saml: { sign_on_url: idpUrl, public_certificate: idpKey.certificate, ...saml },
      },
      { login: "plain" },
    ],
  });
  return { app, store };
}

function acme(store: Store) {
  return getGitHubStore(store).orgs.findOneBy("login", "acme")!;
}

function userId(store: Store, login: string) {
  return getGitHubStore(store).users.findOneBy("login", login)!.id;
}

describe("GitHub organization SAML metadata", () => {
  it("publishes the organization's service provider metadata", async () => {
    const { app } = createTestApp();
    const res = await app.request(`${base}/orgs/acme/saml/metadata`);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("xml");
    const doc = new DOMParser().parseFromString(await res.text(), "text/xml");
    const descriptor = doc.documentElement!;
    expect(descriptor.localName).toBe("EntityDescriptor");
    expect(descriptor.getAttribute("entityID")).toBe(entityId);
    const acs = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata", "AssertionConsumerService")[0];
    expect(acs.getAttribute("Location")).toBe(acsUrl);
    expect(acs.getAttribute("Binding")).toBe("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
  });

  it("returns 404 for an organization without SAML single sign-on", async () => {
    const { app } = createTestApp();
    expect((await app.request(`${base}/orgs/plain/saml/metadata`)).status).toBe(404);
    expect((await app.request(`${base}/orgs/plain/sso`)).status).toBe(404);
  });
});

describe("GitHub organization SAML sign-in request", () => {
  it("asks a browser without a GitHub session to sign in to its personal account first", async () => {
    const { app } = createTestApp();
    const res = await app.request(`${base}/orgs/acme/sso`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Sign in to GitHub");
    expect(html).toContain('action="/login/oauth/callback"');
    expect(hiddenField(html, "redirect_uri")).toBe(`${base}/orgs/acme/sso`);
    expect(hiddenField(html, "SAMLRequest")).toBeNull();
  });

  it("does not take the API fallback user as a browser session", async () => {
    const { app } = createTestApp();
    const res = await app.request(`${base}/orgs/acme/sso`, { headers: { Authorization: "Bearer unknown" } });
    expect(hiddenField(await res.text(), "SAMLRequest")).toBeNull();
  });

  it("posts an AuthnRequest to the identity provider for a signed-in browser", async () => {
    const { app } = createTestApp();
    const sessionId = await signIn(app, "octocat");
    const { html } = await startSso(app, sessionId, "?return_to=%2Facme%2Frepo");
    expect(html).toContain(`action="${idpUrl}"`);
    expect(hiddenField(html, "RelayState")).toBe("/acme/repo");

    const xml = Buffer.from(hiddenField(html, "SAMLRequest")!, "base64").toString("utf8");
    const request = new DOMParser().parseFromString(xml, "text/xml").documentElement!;
    expect(request.localName).toBe("AuthnRequest");
    expect(request.namespaceURI).toBe(SAMLP_NS);
    expect(request.getAttribute("ID")).toMatch(/^_[0-9a-f]+$/);
    expect(request.getAttribute("Destination")).toBe(idpUrl);
    expect(request.getAttribute("AssertionConsumerServiceURL")).toBe(acsUrl);
    expect(request.getAttribute("ProtocolBinding")).toBe("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
    expect(request.getElementsByTagNameNS(SAML_NS, "Issuer")[0].textContent).toBe(entityId);
  });
});

describe("GitHub organization SAML response", () => {
  let app: Hono;
  let store: Store;
  let sessionId: string;

  beforeEach(async () => {
    ({ app, store } = createTestApp());
    sessionId = await signIn(app, "octocat");
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  async function expectRefused(xmlFor: (requestId: string) => string, status = 403) {
    const { requestId } = await startSso(app, sessionId);
    const res = await consume(app, sessionId, xmlFor(requestId));
    expect(res.status).toBe(status);
    const html = await res.text();
    expect(html).toContain("SAML sign-in failed");
    expect(getActiveSamlSession(store, sessionId, acme(store).id)).toBeNull();
    return html;
  }

  it("opens a SAML session and links the NameID for a valid signed assertion", async () => {
    const { requestId } = await startSso(app, sessionId);
    const res = await consume(app, sessionId, buildResponse({ requestId }), "/acme/repo");
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/acme/repo");

    const session = getActiveSamlSession(store, sessionId, acme(store).id);
    expect(session?.name_id).toBe("octocat@acme.test");
    expect(session?.user_id).toBe(userId(store, "octocat"));
    expect(getLinkedSamlIdentity(store, acme(store).id, userId(store, "octocat"))).toBe("octocat@acme.test");
    expect(getActiveSamlSession(store, "another-browser", acme(store).id)).toBeNull();
  });

  it("accepts a signed response and redirects to the organization without RelayState", async () => {
    const { requestId } = await startSso(app, sessionId);
    const res = await consume(app, sessionId, buildResponse({ requestId, sign: "response" }));
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/orgs/acme");
    expect(getActiveSamlSession(store, sessionId, acme(store).id)).not.toBeNull();
  });

  it("does not redirect to another host from RelayState", async () => {
    for (const relayState of [
      "/\t/evil.example/",
      "/ /evil.example",
      "//evil.example",
      "/\\evil.example",
      "https://evil.example",
    ]) {
      const { requestId } = await startSso(app, sessionId);
      const res = await consume(app, sessionId, buildResponse({ requestId }), relayState);
      expect(res.status, relayState).toBe(302);
      expect(res.headers.get("Location"), relayState).toBe("/orgs/acme");
    }
  });

  it("redirects to a local RelayState path", async () => {
    const { requestId } = await startSso(app, sessionId);
    const res = await consume(app, sessionId, buildResponse({ requestId }), "/acme/repo?tab=code#readme");
    expect(res.headers.get("Location")).toBe("/acme/repo?tab=code#readme");
  });

  it("does not send an external return_to as RelayState", async () => {
    const { html } = await startSso(app, sessionId, `?return_to=${encodeURIComponent("/\t/evil.example/")}`);
    expect(hiddenField(html, "RelayState")).toBeNull();
  });

  it("refuses an unsigned response", async () => {
    await expectRefused((requestId) => buildResponse({ requestId, sign: "none" }));
  });

  it("refuses a response signed by another key", async () => {
    await expectRefused((requestId) => buildResponse({ requestId, key: otherKey }));
    await expectRefused((requestId) => buildResponse({ requestId, key: otherKey, sign: "response" }));
    await expectRefused((requestId) => buildResponse({ requestId, key: otherKey, keyInfo: true }));
  });

  it("refuses a signed assertion modified after signing", async () => {
    await expectRefused((requestId) => buildResponse({ requestId }).replace("octocat@acme.test", "hubot@acme.test"));
  });

  it("refuses a response with a second, unsigned assertion next to the signed one", async () => {
    const forged = (requestId: string) =>
      buildResponse({ requestId, sign: "none", nameId: "hubot@acme.test" })
        .match(/<saml:Assertion[\s\S]*<\/saml:Assertion>/)![0]
        .replace('ID="_assertion1"', 'ID="_forged"');
    const before = await expectRefused((requestId) =>
      buildResponse({ requestId }).replace("</samlp:Status>", `</samlp:Status>${forged(requestId)}`),
    );
    expect(before).toContain("single assertion");
    const after = await expectRefused((requestId) =>
      buildResponse({ requestId }).replace("</samlp:Response>", `${forged(requestId)}</samlp:Response>`),
    );
    expect(after).toContain("single assertion");
  });

  it("reads the signed assertion, not an unsigned copy wrapped around it", async () => {
    await expectRefused((requestId) => {
      const signed = buildResponse({ requestId });
      const signedAssertion = signed.match(/<saml:Assertion[\s\S]*<\/saml:Assertion>/)![0];
      const forged = buildResponse({ requestId, sign: "none", nameId: "hubot@acme.test" })
        .match(/<saml:Assertion[\s\S]*<\/saml:Assertion>/)![0]
        .replace("</saml:Subject>", `</saml:Subject><saml:Advice>${signedAssertion}</saml:Advice>`);
      return signed.replace(signedAssertion, forged);
    });
  });

  it("refuses a response for another audience", async () => {
    await expectRefused((requestId) => buildResponse({ requestId, audience: `${base}/orgs/other` }));
  });

  it("refuses a response for another recipient", async () => {
    await expectRefused((requestId) => buildResponse({ requestId, recipient: `${base}/orgs/other/saml/consume` }));
  });

  it("refuses a signed response for another destination", async () => {
    await expectRefused((requestId) =>
      buildResponse({ requestId, sign: "response", destination: `${base}/orgs/other/saml/consume` }),
    );
  });

  it("refuses an expired response", async () => {
    await expectRefused((requestId) =>
      buildResponse({
        requestId,
        notBefore: new Date(Date.now() - 10 * 60 * 1000),
        notOnOrAfter: new Date(Date.now() - 60 * 1000),
      }),
    );
  });

  it("refuses a response that is not yet valid", async () => {
    await expectRefused((requestId) =>
      buildResponse({
        requestId,
        notBefore: new Date(Date.now() + 60 * 1000),
        notOnOrAfter: new Date(Date.now() + 10 * 60 * 1000),
      }),
    );
  });

  it("refuses a response to an unknown request, to no request, or to another browser's request", async () => {
    await expectRefused(() => buildResponse({ requestId: "_unknown" }));
    await expectRefused(() => buildResponse({ requestId: null }));

    const otherSession = await signIn(app, "hubot");
    const { requestId } = await startSso(app, otherSession);
    const res = await consume(app, sessionId, buildResponse({ requestId }));
    expect(res.status).toBe(403);
  });

  it("refuses a replayed response", async () => {
    const { requestId } = await startSso(app, sessionId);
    const xml = buildResponse({ requestId });
    expect((await consume(app, sessionId, xml)).status).toBe(302);
    expect((await consume(app, sessionId, xml)).status).toBe(403);
  });

  async function linkFirstIdentity() {
    const first = await startSso(app, sessionId);
    expect((await consume(app, sessionId, buildResponse({ requestId: first.requestId }))).status).toBe(302);
    sessionId = await signIn(app, "octocat");
  }

  async function startRelink(relayState?: string): Promise<string> {
    const { requestId } = await startSso(app, sessionId);
    const res = await consume(app, sessionId, buildResponse({ requestId, nameId: "new@acme.test" }), relayState);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("You are about to relink your account.");
    expect(html).toContain('action="/orgs/acme/saml/relink"');
    return hiddenField(html, "relink_token")!;
  }

  function confirmRelink(browserSession: string, token: string) {
    return app.request(`${base}/orgs/acme/saml/relink`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: `_emu_session=${browserSession}` },
      body: new URLSearchParams({ relink_token: token }),
    });
  }

  it("warns before relinking the account to a different NameID", async () => {
    await linkFirstIdentity();
    const token = await startRelink();
    expect(token).toMatch(/^[0-9a-f]+$/);
    expect(getLinkedSamlIdentity(store, acme(store).id, userId(store, "octocat"))).toBe("octocat@acme.test");
    expect(getActiveSamlSession(store, sessionId, acme(store).id)).toBeNull();
  });

  it("relinks the account and opens the SAML session when the user continues", async () => {
    await linkFirstIdentity();
    const token = await startRelink("/acme/repo");
    const res = await confirmRelink(sessionId, token);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/acme/repo");
    expect(getLinkedSamlIdentity(store, acme(store).id, userId(store, "octocat"))).toBe("new@acme.test");
    expect(getActiveSamlSession(store, sessionId, acme(store).id)?.name_id).toBe("new@acme.test");
    expect((await confirmRelink(sessionId, token)).status).toBe(403);
  });

  it("relinks after a response posted without the session cookie, from GitHub's own page", async () => {
    await linkFirstIdentity();
    const { requestId } = await startSso(app, sessionId);
    const warning = await consume(app, null, buildResponse({ requestId, nameId: "new@acme.test" }));
    expect(warning.status).toBe(200);
    const token = hiddenField(await warning.text(), "relink_token")!;
    expect((await confirmRelink("unknown-session", token)).status).toBe(403);
    expect((await confirmRelink(sessionId, token)).status).toBe(302);
    expect(getActiveSamlSession(store, sessionId, acme(store).id)?.name_id).toBe("new@acme.test");
  });

  it("changes nothing without the user's confirmation", async () => {
    await linkFirstIdentity();
    const token = await startRelink();
    const otherBrowser = await signIn(app, "octocat");
    expect((await confirmRelink(otherBrowser, token)).status).toBe(403);
    expect((await confirmRelink(sessionId, "unknown")).status).toBe(403);
    expect(getLinkedSamlIdentity(store, acme(store).id, userId(store, "octocat"))).toBe("octocat@acme.test");
    expect(getActiveSamlSession(store, sessionId, acme(store).id)).toBeNull();
    expect(getActiveSamlSession(store, otherBrowser, acme(store).id)).toBeNull();
  });

  it("refuses a NameID linked to another account", async () => {
    const first = await startSso(app, sessionId);
    expect((await consume(app, sessionId, buildResponse({ requestId: first.requestId }))).status).toBe(302);

    sessionId = await signIn(app, "hubot");
    await expectRefused((requestId) => buildResponse({ requestId }));
    expect(getLinkedSamlIdentity(store, acme(store).id, userId(store, "hubot"))).toBeNull();
  });

  it("accepts a cross-site POST without the session cookie for the browser that sent the request", async () => {
    const otherSession = await signIn(app, "hubot");
    const { requestId } = await startSso(app, sessionId);
    const res = await consume(app, null, buildResponse({ requestId }), "/acme/repo");
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/acme/repo");

    expect(getActiveSamlSession(store, sessionId, acme(store).id)?.user_id).toBe(userId(store, "octocat"));
    expect(getActiveSamlSession(store, otherSession, acme(store).id)).toBeNull();
    expect(getLinkedSamlIdentity(store, acme(store).id, userId(store, "octocat"))).toBe("octocat@acme.test");
    expect(getLinkedSamlIdentity(store, acme(store).id, userId(store, "hubot"))).toBeNull();
    expect((await consume(app, null, buildResponse({ requestId }))).status).toBe(403);
  });

  it("does not open a session for the browser that posts a response to another browser's request", async () => {
    const posterSession = await signIn(app, "hubot");
    const { requestId } = await startSso(app, sessionId);
    const res = await consume(app, posterSession, buildResponse({ requestId }));
    expect(res.status).toBe(403);
    expect(getActiveSamlSession(store, posterSession, acme(store).id)).toBeNull();
    expect(getActiveSamlSession(store, sessionId, acme(store).id)).toBeNull();
    expect(getLinkedSamlIdentity(store, acme(store).id, userId(store, "hubot"))).toBeNull();
  });

  it("refuses a response that is not SAML", async () => {
    await startSso(app, sessionId);
    const res = await consume(app, sessionId, "not xml");
    expect(res.status).toBe(400);
  });

  it("ends the SAML session 24 hours after authentication", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
    const { requestId } = await startSso(app, sessionId);
    expect((await consume(app, sessionId, buildResponse({ requestId }))).status).toBe(302);

    vi.setSystemTime(new Date("2026-01-01T23:59:59Z"));
    expect(getActiveSamlSession(store, sessionId, acme(store).id)).not.toBeNull();
    vi.setSystemTime(new Date("2026-01-02T00:00:00Z"));
    expect(getActiveSamlSession(store, sessionId, acme(store).id)).toBeNull();
    expect(getLinkedSamlIdentity(store, acme(store).id, userId(store, "octocat"))).toBe("octocat@acme.test");
  });

  it("ends the SAML session at SessionNotOnOrAfter", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
    const { requestId } = await startSso(app, sessionId);
    const sessionNotOnOrAfter = new Date("2026-01-01T04:00:00Z");
    expect((await consume(app, sessionId, buildResponse({ requestId, sessionNotOnOrAfter }))).status).toBe(302);

    vi.setSystemTime(new Date("2026-01-01T03:59:59Z"));
    expect(getActiveSamlSession(store, sessionId, acme(store).id)).not.toBeNull();
    vi.setSystemTime(sessionNotOnOrAfter);
    expect(getActiveSamlSession(store, sessionId, acme(store).id)).toBeNull();
  });

  it("checks the issuer when the organization configures one", async () => {
    ({ app, store } = createTestApp({ issuer: idpIssuer }));
    sessionId = await signIn(app, "octocat");
    await expectRefused((requestId) => buildResponse({ requestId, issuer: "http://www.okta.com/other" }));

    const { requestId } = await startSso(app, sessionId);
    expect((await consume(app, sessionId, buildResponse({ requestId }))).status).toBe(302);
  });
});

describe("GitHub organization SAML seed config", () => {
  it("requires the sign-on URL and the public certificate", () => {
    const { store } = createServer(githubPlugin, { baseUrl: base });
    expect(() =>
      seedFromConfig(store, base, {
        orgs: [{ login: "acme", saml: { sign_on_url: idpUrl, public_certificate: "" } }],
      }),
    ).toThrow(/public_certificate/);
  });
});
