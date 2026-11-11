import { DOMParser, type Document, type Element } from "@xmldom/xmldom";
import { createServer } from "@emulators/core";
import { SignedXml } from "xml-crypto";
import { describe, expect, it } from "vitest";
import { getOktaStore, oktaPlugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";
const EXTERNAL_KEY = "exkSAMLATTRS123456";
const ACS = "https://sp.example.com/saml/acs";
const SP_ENTITY_ID = "https://sp.example.com/metadata";

const NS = {
  assertion: "urn:oasis:names:tc:SAML:2.0:assertion",
  dsig: "http://www.w3.org/2000/09/xmldsig#",
  xsi: "http://www.w3.org/2001/XMLSchema-instance",
};

const FORMAT = {
  basic: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
  uri: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
  unspecified: "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
};

function setup(signOn: Record<string, unknown>) {
  const server = createServer(oktaPlugin, {
    tokens: { "ssws-token": { login: "admin@okta.local", id: 1, scopes: ["okta.*"] } },
    fallbackUser: { login: "testuser@okta.local", id: 1, scopes: ["openid", "profile", "email", "groups"] },
  });
  oktaPlugin.seed?.(server.store, base);
  seedFromConfig(server.store, base, {
    users: [
      {
        okta_id: "00ualice",
        login: "alice@example.com",
        email: "alice.example@example.org",
        first_name: "Alice",
        last_name: "Example",
        display_name: "Alice <Admin> Example",
      },
    ],
    groups: [
      { okta_id: "00gengineering", name: "Engineering" },
      { okta_id: "00gengplatform", name: "Engineering Platform" },
      { okta_id: "00gsales", name: "Sales" },
      { okta_id: "00gnotmember", name: "Engineering Managers" },
    ],
    group_memberships: [
      { group_okta_id: "00gengineering", user_okta_id: "00ualice" },
      { group_okta_id: "00gengplatform", user_okta_id: "00ualice" },
      { group_okta_id: "00gsales", user_okta_id: "00ualice" },
    ],
    apps: [
      {
        okta_id: "0oasaml",
        name: "attrs_saml",
        label: "Attributes SP",
        sign_on_mode: "SAML_2_0",
        external_key: EXTERNAL_KEY,
        settings: { signOn: { ssoAcsUrl: ACS, audience: SP_ENTITY_ID, ...signOn } },
      },
    ],
    app_assignments: [{ app_okta_id: "0oasaml", user_okta_id: "00ualice" }],
  });
  return server;
}

type Server = ReturnType<typeof setup>;

function decodeEntities(value: string): string {
  return value
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

function parseForms(html: string): Array<{ action: string; fields: Record<string, string> }> {
  const forms = [...html.matchAll(/<form[^>]*action="([^"]+)"[^>]*>([\s\S]*?)<\/form>/gi)];
  return forms.map(([, action, inner]) => {
    const fields: Record<string, string> = {};
    for (const [, name, value] of inner.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)"\/>/g)) {
      fields[decodeEntities(name)] = decodeEntities(value);
    }
    return { action: decodeEntities(action), fields };
  });
}

/** Signs Alice in through the IdP-initiated flow and returns the SAML response XML. */
async function samlResponseFor(server: Server, appName = "attrs_saml", externalKey = EXTERNAL_KEY): Promise<string> {
  const picker = await server.app.request(`${base}/app/${appName}/${externalKey}/sso/saml`);
  expect(picker.status).toBe(200);
  const form = parseForms(await picker.text()).find((entry) => entry.fields.user_ref === "00ualice");
  expect(form).toBeDefined();
  const callback = await server.app.request(`${base}${form!.action}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form!.fields).toString(),
  });
  expect(callback.status).toBe(200);
  const posted = parseForms(await callback.text());
  expect(posted).toHaveLength(1);
  return Buffer.from(posted[0].fields.SAMLResponse, "base64").toString("utf-8");
}

function parseXml(xml: string): Document {
  return new DOMParser().parseFromString(xml, "text/xml");
}

function attributesOf(doc: Document): Array<{ name: string; nameFormat: string; values: string[] }> {
  return [...doc.getElementsByTagNameNS(NS.assertion, "Attribute")].map((attribute) => ({
    name: attribute.getAttribute("Name")!,
    nameFormat: attribute.getAttribute("NameFormat")!,
    values: [...attribute.getElementsByTagNameNS(NS.assertion, "AttributeValue")].map((value) => value.textContent!),
  }));
}

function signatureOf(element: Element): Element | undefined {
  for (let node = element.firstChild; node; node = node.nextSibling) {
    if (node.nodeType === 1 && (node as Element).localName === "Signature" && node.namespaceURI === NS.dsig) {
      return node as Element;
    }
  }
  return undefined;
}

async function verify(server: Server, xml: string, signature: Element): Promise<boolean> {
  const metadata = await (await server.app.request(`${base}/app/${EXTERNAL_KEY}/sso/saml/metadata`)).text();
  const cert = metadata.match(/<ds:X509Certificate>([^<]+)<\/ds:X509Certificate>/)![1];
  const sig = new SignedXml({ publicCert: `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----` });
  sig.loadSignature(signature.toString());
  return sig.checkSignature(xml);
}

function groupStatement(filterType: string, filterValue: string, namespace = FORMAT.basic) {
  return { type: "GROUP", name: "groups", namespace, filterType, filterValue };
}

describe("Okta SAML 2.0 attribute statements", () => {
  it("adds expression attributes with the NameFormat of each namespace, Basic by default", async () => {
    const server = setup({
      attributeStatements: [
        { type: "EXPRESSION", name: "first_name", namespace: FORMAT.basic, values: ["user.firstName"] },
        { type: "EXPRESSION", name: "last_name", namespace: FORMAT.uri, values: ["user.lastName"] },
        { type: "EXPRESSION", name: "User.Email", namespace: FORMAT.unspecified, values: ["user.email"] },
        { type: "EXPRESSION", name: "login", values: ["user.login"] },
        { type: "EXPRESSION", name: "names", namespace: FORMAT.basic, values: ["user.displayName", "user.login"] },
      ],
    });
    const doc = parseXml(await samlResponseFor(server));

    expect(attributesOf(doc)).toEqual([
      { name: "first_name", nameFormat: FORMAT.basic, values: ["Alice"] },
      { name: "last_name", nameFormat: FORMAT.uri, values: ["Example"] },
      { name: "User.Email", nameFormat: FORMAT.unspecified, values: ["alice.example@example.org"] },
      { name: "login", nameFormat: FORMAT.basic, values: ["alice@example.com"] },
      { name: "names", nameFormat: FORMAT.basic, values: ["Alice <Admin> Example", "alice@example.com"] },
    ]);
    for (const value of [...doc.getElementsByTagNameNS(NS.assertion, "AttributeValue")]) {
      expect(value.getAttributeNS(NS.xsi, "type")).toBe("xs:string");
    }

    const assertion = doc.getElementsByTagNameNS(NS.assertion, "Assertion")[0];
    const children = [...assertion.childNodes].filter((node) => node.nodeType === 1).map((node) => node.localName);
    expect(children.slice(-2)).toEqual(["AuthnStatement", "AttributeStatement"]);
  });

  it("leaves out values whose expression is not a documented user profile attribute", async () => {
    const server = setup({
      attributeStatements: [
        { type: "EXPRESSION", name: "User.Username", namespace: FORMAT.basic, values: ["user.userName"] },
        {
          type: "EXPRESSION",
          name: "mixed",
          namespace: FORMAT.basic,
          values: ['user.firstName + " " + user.lastName', "user.email"],
        },
      ],
    });
    const doc = parseXml(await samlResponseFor(server));
    expect(attributesOf(doc)).toEqual([
      { name: "mixed", nameFormat: FORMAT.basic, values: ["alice.example@example.org"] },
    ]);
  });

  it.each([
    ["STARTS_WITH", "Engineering", ["Engineering", "Engineering Platform"]],
    ["EQUALS", "Engineering", ["Engineering"]],
    ["CONTAINS", "ng", ["Engineering", "Engineering Platform"]],
    ["REGEX", ".*", ["Engineering", "Engineering Platform", "Sales"]],
    ["REGEX", "Eng.*|Sales", ["Engineering", "Engineering Platform", "Sales"]],
    ["REGEX", "Engineer", []],
  ])("adds the user's groups matching a %s %s group filter", async (filterType, filterValue, expected) => {
    const server = setup({ attributeStatements: [groupStatement(filterType, filterValue, FORMAT.uri)] });
    const doc = parseXml(await samlResponseFor(server));
    const attributes = attributesOf(doc);
    if (expected.length === 0) {
      expect(doc.getElementsByTagNameNS(NS.assertion, "AttributeStatement")).toHaveLength(0);
      return;
    }
    expect(attributes).toHaveLength(1);
    expect(attributes[0].name).toBe("groups");
    expect(attributes[0].nameFormat).toBe(FORMAT.uri);
    expect([...attributes[0].values].sort()).toEqual([...expected].sort());
  });

  it("signs the assertion and the response over the attribute statement", async () => {
    const server = setup({
      responseSigned: true,
      assertionSigned: true,
      attributeStatements: [
        { type: "EXPRESSION", name: "first_name", namespace: FORMAT.basic, values: ["user.firstName"] },
        groupStatement("STARTS_WITH", "Engineering"),
      ],
    });
    const xml = await samlResponseFor(server);
    const doc = parseXml(xml);
    const assertion = doc.getElementsByTagNameNS(NS.assertion, "Assertion")[0];
    expect(doc.getElementsByTagNameNS(NS.assertion, "AttributeStatement")).toHaveLength(1);

    expect(await verify(server, xml, signatureOf(assertion)!)).toBe(true);
    expect(await verify(server, xml, signatureOf(doc.documentElement!)!)).toBe(true);

    const tampered = xml.replace(">Alice</saml2:AttributeValue>", ">Mallory</saml2:AttributeValue>");
    expect(tampered).not.toBe(xml);
    const tamperedAssertion = parseXml(tampered).getElementsByTagNameNS(NS.assertion, "Assertion")[0];
    expect(await verify(server, tampered, signatureOf(tamperedAssertion)!)).toBe(false);
  });

  it("uses attribute statements of an app created through the Apps API", async () => {
    const server = setup({});
    const created = await server.app.request(`${base}/api/v1/apps`, {
      method: "POST",
      headers: { Authorization: "SSWS ssws-token", "Content-Type": "application/json" },
      body: JSON.stringify({
        name: "api_saml",
        label: "API SAML",
        signOnMode: "SAML_2_0",
        settings: {
          signOn: {
            ssoAcsUrl: ACS,
            audience: SP_ENTITY_ID,
            attributeStatements: [{ type: "EXPRESSION", name: "last_name", values: ["user.lastName"] }],
          },
        },
      }),
    });
    expect(created.status).toBe(201);
    const { id } = (await created.json()) as { id: string };
    const assigned = await server.app.request(`${base}/api/v1/apps/${id}/users/00ualice`, {
      method: "PUT",
      headers: { Authorization: "SSWS ssws-token", "Content-Type": "application/json" },
      body: "{}",
    });
    expect(assigned.ok).toBe(true);
    const externalKey = getOktaStore(server.store).apps.findOneBy("okta_id", id)!.external_key!;

    const doc = parseXml(await samlResponseFor(server, "api_saml", externalKey));
    expect(attributesOf(doc)).toEqual([{ name: "last_name", nameFormat: FORMAT.basic, values: ["Example"] }]);
  });

  it("has no AttributeStatement when no attribute statement is configured", async () => {
    for (const signOn of [{}, { attributeStatements: [] }]) {
      const server = setup(signOn);
      const xml = await samlResponseFor(server);
      const doc = parseXml(xml);
      expect(doc.getElementsByTagNameNS(NS.assertion, "AttributeStatement")).toHaveLength(0);
      const assertion = doc.getElementsByTagNameNS(NS.assertion, "Assertion")[0];
      expect(await verify(server, xml, signatureOf(assertion)!)).toBe(true);
    }
  });
});
