import { expect } from "vitest";
import { DOMParser } from "@xmldom/xmldom";
import { SignedXml } from "xml-crypto";
import type { Hono } from "@emulators/core";

// Shared by the organization SAML tests: an identity provider key, signed responses, and the browser flow.
export const base = "http://localhost:4000";
export const idpUrl = "http://localhost:4100/app/acme_github/exk1/sso/saml";
export const idpIssuer = "http://www.okta.com/exk1";
export const entityId = `${base}/orgs/acme`;
export const acsUrl = `${base}/orgs/acme/saml/consume`;
export const SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
export const SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

export interface TestKey {
  certificate: string;
  privateKey: string;
}

// Self-signed test certificates and keys (openssl req -x509 -newkey rsa:2048 -sha256 -days 36500).
export const idpKey: TestKey = {
  certificate: `-----BEGIN CERTIFICATE-----
MIIDETCCAfmgAwIBAgIUY3eTbkq38rQqB4unj68doMXBXpgwDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMVGVzdCBJZFAgaWRwMCAXDTI2MTExMTE3MzgxMloYDzIx
MjYxMDE4MTczODEyWjAXMRUwEwYDVQQDDAxUZXN0IElkUCBpZHAwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCaZFZGl7q0bmkhXacO+M3czUBcHkvrIzon
1pGHC47cq4FbrAVZ+dnOY1KeKsGyNloz5W6JVTKhjl/KJ+27ChOWe2DWd7KxzSIp
zwwu+f7IrEcStPoOsf5kjgRuosnhk7SV9H68FsM9RyTa4kRRRPlmENr96q69zLsI
6H9Eajo0ZOmyHvc2J76pCWSXCbkj9Bsjx371P7AhEsA+tPsRmvJczGGV2tXBdJVD
CuRcJuMsSKn+MCe/cfMVasUO9GAhQZdrExZVfTXRNrCld8V8tzHtd+9ISHSNMTyY
9UIUCccgDRfAxkgowE8POE47MaY32AXx/wHGezGfRsR+iNeJUgYvAgMBAAGjUzBR
MB0GA1UdDgQWBBS83+WDDRNoRFTGjcJviiXbACQBqjAfBgNVHSMEGDAWgBS83+WD
DRNoRFTGjcJviiXbACQBqjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQBXZNR6RXPLdETrrTybuw3Ncay1cUv3jfAIf3ki3lZwXFHa7ITRagkdPqyi
EX/knszj2GuuWd+MaprUmgKQv6wVm4aUuPs6n27Gud5xyJ+/7drHJhCAgGg5nOpd
AwBb5JTjN/mxmXMFyn+GI5HtkYDTxhjb1mLafVrndxd7Cbswt1/XzpR9+mAigmOV
uMedZl/C9LrbK0/lDvv+4inBFS2cTNsbo5JNj9zFE0UvyhKqR/gzUzakOXtpub0t
jBZdilfoO6B15sWbaANImaBlNxccIouGfnZQZXW3XCyeDyUgYbNHObce9Hn0HHhr
yohVL7MkWVq8Ilt54rq2UxQko1SQ
-----END CERTIFICATE-----`,
  privateKey: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCaZFZGl7q0bmkh
XacO+M3czUBcHkvrIzon1pGHC47cq4FbrAVZ+dnOY1KeKsGyNloz5W6JVTKhjl/K
J+27ChOWe2DWd7KxzSIpzwwu+f7IrEcStPoOsf5kjgRuosnhk7SV9H68FsM9RyTa
4kRRRPlmENr96q69zLsI6H9Eajo0ZOmyHvc2J76pCWSXCbkj9Bsjx371P7AhEsA+
tPsRmvJczGGV2tXBdJVDCuRcJuMsSKn+MCe/cfMVasUO9GAhQZdrExZVfTXRNrCl
d8V8tzHtd+9ISHSNMTyY9UIUCccgDRfAxkgowE8POE47MaY32AXx/wHGezGfRsR+
iNeJUgYvAgMBAAECggEADwvmSJzy6jC0eDb7V/8xeOpb8l5VgcX+HfHQXvvmYWUp
hzidkOZDrtSJMbbzB546bkJW4nV2KL6KYVZA2fCidhDyIBSsSp22TaLLCiz9Aquf
hZgzookAROZ+UhX1XNGbUN3yF/yT7H3pfpd8lvsE30iXPxXHD+JK/BREivNbVs20
JIjaAlZlmqr/sAUmH/2ZFnpnwh46Gbu3hRO1NV2pKkvzx9p+Vh85ijvjFUJsOYxf
pe34JhJVH6RIPjPIw0IbrwaSvxgVL+uNR0lSUvNjuYCzCMnlUN5pAn++lCjB2SxG
iVAGBYl8v8TvxUeKs5kIjdHHKsJgvhbe8FggaqfwSQKBgQDHxXORJzeMlYOVJdPb
7CrH0EhIt4vQWCy/vwMk4VBtiKJ5SXZaX4TyihFsCYXdfc3zCMleAeaUwfcblD2e
Q3E7mLQ1ohM//SCEgp6sPdu173a8BgjeEX+SecCIf2YNyumPpjUHJqndSTscvCF4
G/8rusuYbjxaIewWsXM+ldUMfQKBgQDF2RHnttKyseZ48h5pIvSHtaL0fI0GyRsu
CiBzL0EUFNmzjx34nMDLRD2D+wfkS36N+7WqRlzyRHw0OMdkeZ2T7i1EHbd3aVw6
DQULID8jxv75Zth0Q1m7FHlXWE21fNB+nvlU/H73HS3AGOxZHExw7XpQ6eEmwIGO
h2uU6V+ZGwKBgD8n9kxKeK5SSmIprlvVwwSenWuX03TPm34XNjg/nzyxuKPdjLQv
hIllCvL7471NW4HdIkQ9F5ep5qRqbjyNl8u+kCJwleNh9BjQbreHauGOzhvNUJpc
L9ev9CVzGWF85/AJHLShDYyu7Sg9ddtSBo7dpCYRm7TnCot2GDgOCGfFAoGAYsP2
GEI/9EyyzPWxELMOdyDJdFso25ZRJy6O/HE+f5PZCbYMNCusYsxyGQyb5+94AdEB
4zq084wUpM0jXJkJfOuNVU+wYsAJ9kDBn8g9PNL+PeqFa6Sjiqyx1lSSlmL0ggFC
XpadmybJy/elJObnkgg642GdsAaxpkEcB35o5rkCgYEAofxn+xbTYzk7ZF7Dni/e
/5DCDFxZWnORGDXIn1c0wQeStaIoWwHEGzrXGZNF1LFkr4C/mx7dSViCjuhy8mTT
K2Tel2peet2bfZEt/c5s2yvJgCF6sKD7vpxkaVJIdr97mF2UQPMVPUX7ABk14GEj
qb/bgFNGGwlQ6haw3DQDy8Q=
-----END PRIVATE KEY-----`,
};

export const otherKey: TestKey = {
  certificate: `-----BEGIN CERTIFICATE-----
MIIDFTCCAf2gAwIBAgIUYQsL0MKRk8/x/G+zO8HiYVkexdQwDQYJKoZIhvcNAQEL
BQAwGTEXMBUGA1UEAwwOVGVzdCBJZFAgb3RoZXIwIBcNMjYxMTExMTczODEyWhgP
MjEyNjEwMTgxNzM4MTJaMBkxFzAVBgNVBAMMDlRlc3QgSWRQIG90aGVyMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArfaMQTCw02zPUbBcWX1ZVCaDb1iH
JXFPyxYQTFcf1QNqxA4UwytGtqPZ58hlI+bwz+aT37+rnXxmYN4q4d+IY0OtSwaV
7WON04KayLjgt6BYYBvvuWVU/of0m0tNGsGlZTqwJ0bYDsdrU8gRLgNVrZfLGRI0
hJ+95+8y9AnDLnhFVLxTxQvMhAZ6JRlJ71kbSB3KBEnXqVDqtJTrYUIELQmC8xOh
5VUWhDNmWZf0Fyxy2AkdD+OBWb8seF1MqGeyMGE2o5Je3Df59Md7AovzqX1eRWtO
rLr4HJXzeoeZMU3J9lVOzmVWejS9foD8P5g6gIW/mgf43X2mASp2+2b1rwIDAQAB
o1MwUTAdBgNVHQ4EFgQU6ULtQaPxxv6iB8+5fk6cHty1Vs8wHwYDVR0jBBgwFoAU
6ULtQaPxxv6iB8+5fk6cHty1Vs8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEASpY2vOjWNJFOq2Uij8gnu6ZBdg1lmi5bFvu4I+6zD22xtj1PBsOe
Z+G/fCVT8GK3cCNJiU+S+POLA+eRA4702B/HFpR97DsjlyQRkPkN+tAn8qqywr0j
8v1hWSzkRIKmc4UuCTmModoiCIPZVL6of5mNCkk97DwzyOT0uObGHiPPV0djGCwf
MAlLyZj5D7+6lZ93PawN4O1wYenn99iqKxnR5qRUxIBssMYDR8rc0RacwiaJZDuC
DxH3BS7+EkvtYETArPsb76hnTCG7up1O7fz1A/58K7Dexlk2Z0E9tpAAiu4kqCA2
psOZUMtN9Qrw0pKzE1Kq6X68qxwoxWAQew==
-----END CERTIFICATE-----`,
  privateKey: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCt9oxBMLDTbM9R
sFxZfVlUJoNvWIclcU/LFhBMVx/VA2rEDhTDK0a2o9nnyGUj5vDP5pPfv6udfGZg
3irh34hjQ61LBpXtY43TgprIuOC3oFhgG++5ZVT+h/SbS00awaVlOrAnRtgOx2tT
yBEuA1Wtl8sZEjSEn73n7zL0CcMueEVUvFPFC8yEBnolGUnvWRtIHcoESdepUOq0
lOthQgQtCYLzE6HlVRaEM2ZZl/QXLHLYCR0P44FZvyx4XUyoZ7IwYTajkl7cN/n0
x3sCi/OpfV5Fa06suvgclfN6h5kxTcn2VU7OZVZ6NL1+gPw/mDqAhb+aB/jdfaYB
Knb7ZvWvAgMBAAECggEAP3tegDWP+X9WAmXctW1oKSyqvvmry66XYzFofis2+wk1
r1jCG9yRf/m3/Xyj59+RFhT69mYf7qbkR0oblPR49VxPgzbihE/VhA8/g6rvmiLB
zUS0jM+dHgsn6Hmop/Btdkzd1l9kXbRJBrhWCJf/7oqbe0ko8BLI/rfLvMFJQA3Z
dFUcqHZ/CnV6/pQ0836rs3GNHByzayFcRTArhylQOKqmF4HcQvKs6+W7/fYjyUkB
TNoCaVgwX4SOfIGyMWTd4QnDrr5xwtyRGLel1NKJuAxKE9udLZnDmUh6/R0k1Mrb
YWZr3ukq8+jkFbn0Otl5fRX9mnbLPKdp85v8wM4+CQKBgQDumPN/LqDEKw5bfGj8
iDGBiDgmaH9/zYCsVLqpQJSyz99X/gD/HbL2GU9zNz2TEiGhV9SKKUmf6y1MPKgH
PfzSZsDGyBABozs8RnKp2lNqHqOyfYeQLgmkNT7WrbKRW6PcKpFlKCZZCz+Sg7jd
K3SYS23rFSw1VXWtLylMAWYgqQKBgQC6psFMzVGvRY/e3D/Y8Vi7QiO6qJxjmmbJ
EJve+vj+V1ZsFLiB9lpnS6+BQ7eUQyKWIs/ZL+im0AoBZ8VHAnpA3yxMNN4qJhtM
BkJ2wPkwPuh8CE/N3+/gYxpqeExmmzdLSldPCvfghoZmN1zTpwyGT6q3+JAbzi42
Tk891wFilwKBgH1HTBsMdZdq8BfzRADM1gmoZ6srFT8avSQ/PN9frHQTF7dRBF7v
zibP9VqOt8MAMy5POqbstN7GEjvEYYmj75reHvyA0X66oYCtkMlEfKXsvpEavlJj
CebxmjQIcglGr8wLgdo2caQxdsjMZwWiKo9Ik8dqj5LVc3tilvF0jpY5AoGAH2Et
mkXid78QIv2QVl6s9j52V0lFkZFBuofqTKCQ/+GbC+yn4GGUbU1SIj9KO8jVpbwQ
iYj+ah0LsZTKm9eUyhc7EUzKFPf3Gt7qiaCDxFKvLzsOf6QoZecDZ+b1oUJzF1tW
Nlm3tq2nJsQj/QlWl7YJE4jcYXBWYJblx5XAC90CgYEA7kElPPYerpNlUVzIYp6N
7q48vRf2+Hp/FuHQu3wqpNdq7FNeBjFGZL6stPRiT8V6q/lZ9wkarrp21Wy8HNi+
/5wkumswYWC4JetlJ6G1dxqvajRS8g9NMEerRDVPqjovcbByX4DZfXeZrOsiw1JE
9liEO0q3T1vWqkEpJEmua4w=
-----END PRIVATE KEY-----`,
};

export async function signIn(app: Hono, login: string): Promise<string> {
  const res = await app.request(`${base}/login/oauth/callback`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ login, redirect_uri: `${base}/orgs/acme/sso`, scope: "", state: "", client_id: "" }),
  });
  const cookie = res.headers.get("Set-Cookie") ?? "";
  const match = /_emu_session=([^;]+)/.exec(cookie);
  expect(match).not.toBeNull();
  return match![1];
}

export function hiddenField(html: string, name: string): string | null {
  const match = new RegExp(`name="${name}" value="([^"]*)"`).exec(html);
  return match
    ? match[1]
        .replace(/&#x2F;|&#47;/g, "/")
        .replace(/&amp;/g, "&")
        .replace(/&quot;/g, '"')
    : null;
}

export async function startSso(app: Hono, sessionId: string, query = ""): Promise<{ html: string; requestId: string }> {
  const res = await app.request(`${base}/orgs/acme/sso${query}`, { headers: { Cookie: `_emu_session=${sessionId}` } });
  expect(res.status).toBe(200);
  const html = await res.text();
  const samlRequest = hiddenField(html, "SAMLRequest");
  expect(samlRequest).not.toBeNull();
  const request = new DOMParser().parseFromString(Buffer.from(samlRequest!, "base64").toString("utf8"), "text/xml");
  return { html, requestId: request.documentElement!.getAttribute("ID")! };
}

export interface ResponseOptions {
  requestId?: string | null;
  nameId?: string;
  audience?: string;
  recipient?: string;
  destination?: string;
  issuer?: string;
  notBefore?: Date;
  notOnOrAfter?: Date;
  sessionNotOnOrAfter?: Date;
  sign?: "assertion" | "response" | "none";
  key?: TestKey;
  keyInfo?: boolean;
}

export function buildResponse(options: ResponseOptions = {}): string {
  const now = Date.now();
  const issuer = options.issuer ?? idpIssuer;
  const inResponseTo = options.requestId === null ? "" : ` InResponseTo="${options.requestId}"`;
  const notBefore = (options.notBefore ?? new Date(now - 5 * 60 * 1000)).toISOString();
  const notOnOrAfter = (options.notOnOrAfter ?? new Date(now + 5 * 60 * 1000)).toISOString();
  const sessionNotOnOrAfter = options.sessionNotOnOrAfter
    ? ` SessionNotOnOrAfter="${options.sessionNotOnOrAfter.toISOString()}"`
    : "";
  const issueInstant = new Date(now).toISOString();
  const xml =
    `<samlp:Response xmlns:samlp="${SAMLP_NS}" xmlns:saml="${SAML_NS}" ID="_response1" Version="2.0"` +
    ` IssueInstant="${issueInstant}" Destination="${options.destination ?? acsUrl}"${inResponseTo}>` +
    `<saml:Issuer>${issuer}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
    `<saml:Assertion ID="_assertion1" Version="2.0" IssueInstant="${issueInstant}">` +
    `<saml:Issuer>${issuer}</saml:Issuer>` +
    `<saml:Subject>` +
    `<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">${options.nameId ?? "octocat@acme.test"}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
    `<saml:SubjectConfirmationData${inResponseTo} NotOnOrAfter="${notOnOrAfter}" Recipient="${options.recipient ?? acsUrl}"/>` +
    `</saml:SubjectConfirmation>` +
    `</saml:Subject>` +
    `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">` +
    `<saml:AudienceRestriction><saml:Audience>${options.audience ?? entityId}</saml:Audience></saml:AudienceRestriction>` +
    `</saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${issueInstant}"${sessionNotOnOrAfter}>` +
    `<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>` +
    `</saml:AuthnStatement>` +
    `</saml:Assertion>` +
    `</samlp:Response>`;

  const sign = options.sign ?? "assertion";
  if (sign === "none") return xml;
  const target = sign === "assertion" ? "Assertion" : "Response";
  const signer = new SignedXml({
    privateKey: (options.key ?? idpKey).privateKey,
    publicCert: options.keyInfo ? (options.key ?? idpKey).certificate : undefined,
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  });
  signer.addReference({
    xpath: `//*[local-name(.)='${target}']`,
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
  });
  signer.computeSignature(xml, {
    location: { reference: `//*[local-name(.)='${target}']/*[local-name(.)='Issuer']`, action: "after" },
  });
  return signer.getSignedXml();
}

/** Posts the response as the browser would; `sessionId: null` is a cross-site POST without the session cookie. */
export function consume(app: Hono, sessionId: string | null, xml: string, relayState?: string) {
  const form = new URLSearchParams({ SAMLResponse: Buffer.from(xml, "utf8").toString("base64") });
  if (relayState !== undefined) form.set("RelayState", relayState);
  return app.request(`${base}/orgs/acme/saml/consume`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...(sessionId === null ? {} : { Cookie: `_emu_session=${sessionId}` }),
    },
    body: form,
  });
}
