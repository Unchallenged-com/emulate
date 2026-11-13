import { connect } from "node:net";
import { hostname } from "node:os";
import { debug, type Store } from "@emulators/core";
import type { GoogleMessage } from "./entities.js";

export interface GoogleSmtpRelayConfig {
  host: string;
  port?: number;
  /** The name the emulator gives in `EHLO`; the machine's host name when not set. */
  helo?: string;
}

const RELAY_KEY = "google.smtp_relay";
const TIMEOUT_MS = 30_000;

export function setSmtpRelay(store: Store, config: GoogleSmtpRelayConfig): void {
  store.setData(RELAY_KEY, config);
}

/**
 * Hands a sent message to the configured SMTP relay for the recipients who are not users of the emulator, the way
 * Gmail reaches recipients outside Google: over SMTP, with the sender's address as the envelope sender. Does nothing
 * when no relay is configured. Runs after the API has answered; failures are only logged.
 */
export function relaySentMessage(store: Store, message: GoogleMessage, recipients: string[], raw: string): void {
  const relay = store.getData<GoogleSmtpRelayConfig>(RELAY_KEY);
  if (!relay || recipients.length === 0) return;

  sendOverSmtp(relay, message.user_email, recipients, Buffer.from(raw, "base64url").toString("utf8")).then(
    (reply) => debug("google.smtp", `[relay] ${message.gmail_id} to ${recipients.join(", ")}: ${reply}`),
    (error: Error) =>
      debug("google.smtp", `[relay] ${message.gmail_id} to ${recipients.join(", ")} failed: ${error.message}`),
  );
}

function sendOverSmtp(relay: GoogleSmtpRelayConfig, sender: string, recipients: string[], content: string) {
  return new Promise<string>((resolve, reject) => {
    const socket = connect({ host: relay.host, port: relay.port ?? 25 });
    socket.setTimeout(TIMEOUT_MS, () => socket.destroy(new Error("timed out")));
    socket.on("error", reject);

    let buffer = "";
    let lines: string[] = [];
    const waiting: Array<(reply: { code: number; text: string }) => void> = [];
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      let end: number;
      while ((end = buffer.indexOf("\r\n")) >= 0) {
        const line = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        lines.push(line);
        // The last line of a reply has a space after its code (RFC 5321, section 4.2.1).
        if (line.charAt(3) !== "-") {
          const reply = { code: Number(line.slice(0, 3)), text: lines.join("\n") };
          lines = [];
          waiting.shift()?.(reply);
        }
      }
    });
    const next = () => new Promise<{ code: number; text: string }>((done) => waiting.push(done));
    const command = async (line: string, expected: number) => {
      const reply = next();
      socket.write(`${line}\r\n`);
      return check(await reply, expected, line);
    };
    const check = (reply: { code: number; text: string }, expected: number, step: string) => {
      if (Math.floor(reply.code / 100) !== expected) throw new Error(`${step}: ${reply.text}`);
      return reply.text;
    };

    (async () => {
      check(await next(), 2, "greeting");
      await command(`EHLO ${relay.helo ?? hostname()}`, 2);
      await command(`MAIL FROM:<${sender}>`, 2);
      for (const recipient of recipients) await command(`RCPT TO:<${recipient}>`, 2);
      await command("DATA", 3);
      // Lines are sent with CRLF, and a line starting with a period gets another one (RFC 5321, section 4.5.2).
      const body = content.replace(/\r?\n/g, "\r\n").replace(/^\./gm, "..");
      const accepted = await command(`${body}${body.endsWith("\r\n") ? "" : "\r\n"}.`, 2);
      await command("QUIT", 2).catch(() => undefined);
      socket.end();
      return accepted;
    })().then(resolve, (error) => {
      socket.destroy();
      reject(error);
    });
  });
}
