import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createServer, type AddressInfo, type Server } from "node:net";
import { Hono } from "@emulators/core";
import {
  Store,
  WebhookDispatcher,
  authMiddleware,
  createApiErrorHandler,
  createErrorHandler,
  type TokenMap,
} from "@emulators/core";
import { googlePlugin, seedFromConfig, type GoogleSeedConfig } from "../index.js";

const base = "http://localhost:4000";

interface Transaction {
  commands: string[];
  data: string;
}

/** An SMTP server that accepts every message and records each transaction. */
function startSmtpServer(rejectRecipient?: string) {
  const transactions: Transaction[] = [];
  const server = createServer((socket) => {
    let current: Transaction = { commands: [], data: "" };
    let inData = false;
    let buffer = "";
    socket.write("220 relay.test ESMTP\r\n");
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      let end: number;
      while ((end = buffer.indexOf("\r\n")) >= 0) {
        const line = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        if (inData) {
          if (line === ".") {
            inData = false;
            transactions.push(current);
            current = { commands: [], data: "" };
            socket.write("250 2.0.0 queued\r\n");
          } else {
            current.data += `${line}\r\n`;
          }
          continue;
        }
        current.commands.push(line);
        if (line.startsWith("EHLO")) socket.write("250-relay.test\r\n250 8BITMIME\r\n");
        else if (line === "DATA") {
          inData = true;
          socket.write("354 go ahead\r\n");
        } else if (line === "QUIT") socket.end("221 bye\r\n");
        else if (rejectRecipient && line === `RCPT TO:<${rejectRecipient}>`) socket.write("550 5.1.1 no such user\r\n");
        else socket.write("250 OK\r\n");
      }
    });
  });
  return new Promise<{ server: Server; port: number; transactions: Transaction[] }>((resolve) =>
    server.listen(0, "127.0.0.1", () =>
      resolve({ server, port: (server.address() as AddressInfo).port, transactions }),
    ),
  );
}

function createTestApp(config: GoogleSeedConfig) {
  const store = new Store();
  const tokenMap: TokenMap = new Map();
  tokenMap.set("token-alice", { login: "alice@example.com", id: 1, scopes: [] });
  const app = new Hono();
  app.onError(createApiErrorHandler());
  app.use("*", createErrorHandler());
  app.use("*", authMiddleware(tokenMap));
  googlePlugin.register(app as any, store, new WebhookDispatcher(), base, tokenMap);
  googlePlugin.seed?.(store, base);
  seedFromConfig(store, base, { users: [{ email: "alice@example.com" }, { email: "bob@example.com" }], ...config });
  return app;
}

async function send(app: Hono, path: string, body: unknown) {
  const res = await app.request(`${base}${path}`, {
    method: "POST",
    headers: { Authorization: "Bearer token-alice", "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as any };
}

async function until<T>(read: () => T | undefined): Promise<T> {
  for (let i = 0; i < 200; i++) {
    const value = read();
    if (value !== undefined) return value;
    await new Promise((done) => setTimeout(done, 10));
  }
  throw new Error("timed out");
}

const raw = Buffer.from(
  [
    "From: alice@example.com",
    "To: bob@example.com, Partner <partner@lab.test>",
    "Bcc: auditor@other.test",
    "Subject: Results",
    "Message-ID: <results-1@example.com>",
    "",
    "Attached.",
    ".hidden line",
    "",
  ].join("\r\n"),
).toString("base64url");

describe("Gmail SMTP relay for recipients outside the emulator", () => {
  let smtp: Awaited<ReturnType<typeof startSmtpServer>>;

  beforeEach(async () => {
    smtp = await startSmtpServer();
  });

  afterEach(() => {
    smtp.server.close();
  });

  it("hands the message to the relay for the other recipients, with the sender as envelope sender", async () => {
    const app = createTestApp({ smtp_relay: { host: "127.0.0.1", port: smtp.port, helo: "emulator.test" } });
    expect((await send(app, "/gmail/v1/users/me/messages/send", { raw })).status).toBe(200);

    const transaction = await until(() => smtp.transactions[0]);
    expect(transaction.commands).toEqual([
      "EHLO emulator.test",
      "MAIL FROM:<alice@example.com>",
      "RCPT TO:<partner@lab.test>",
      "RCPT TO:<auditor@other.test>",
      "DATA",
    ]);
    expect(transaction.data).toContain("Message-ID: <results-1@example.com>\r\n");
    expect(transaction.data).not.toMatch(/^Bcc:/im);
    expect(transaction.data).toContain("\r\n..hidden line\r\n");
  });

  it("relays sent drafts", async () => {
    const app = createTestApp({ smtp_relay: { host: "127.0.0.1", port: smtp.port } });
    const draft = await send(app, "/gmail/v1/users/me/drafts", { message: { raw } });
    expect((await send(app, "/gmail/v1/users/me/drafts/send", { id: draft.body.id })).status).toBe(200);
    const transaction = await until(() => smtp.transactions[0]);
    expect(transaction.commands).toContain("RCPT TO:<partner@lab.test>");
  });

  it("does not contact the relay when every recipient is a user, or when none is configured", async () => {
    const withRelay = createTestApp({ smtp_relay: { host: "127.0.0.1", port: smtp.port } });
    await send(withRelay, "/gmail/v1/users/me/messages/send", { to: "bob@example.com", subject: "Inside" });
    const withoutRelay = createTestApp({});
    expect((await send(withoutRelay, "/gmail/v1/users/me/messages/send", { raw })).status).toBe(200);
    await new Promise((done) => setTimeout(done, 200));
    expect(smtp.transactions).toHaveLength(0);
  });

  it("answers the API request even when the relay refuses a recipient", async () => {
    smtp.server.close();
    smtp = await startSmtpServer("partner@lab.test");
    const app = createTestApp({ smtp_relay: { host: "127.0.0.1", port: smtp.port } });
    const sent = await send(app, "/gmail/v1/users/me/messages/send", { raw });
    expect(sent.status).toBe(200);
    expect(sent.body.labelIds).toEqual(["SENT"]);
  });
});
