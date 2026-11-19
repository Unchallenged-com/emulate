import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "../config-loader.js";
import { prepareProject } from "../project-runner.js";

const CLIENT = {
  client_id: "persist-client.apps.googleusercontent.com",
  client_secret: "persist-secret",
  redirect_uris: ["http://localhost:3000/callback"],
};

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function project(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "emulate-builtin-persistence-"));
  dirs.push(dir);
  return dir;
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as { port: number };
      server.close(() => resolve(port));
    });
  });
}

async function writeConfig(dir: string, port: number, users: string[], persistence = "./state/google.json") {
  const path = join(dir, "emulate.config.json");
  const seed = { strict_scopes: true, users: users.map((email) => ({ email })), oauth_clients: [CLIENT] };
  await writeFile(path, JSON.stringify({ services: { google: { emulator: "google", port, seed, persistence } } }));
  return path;
}

async function run(config: string) {
  const project = await prepareProject({ port: 4000, host: "127.0.0.1", config });
  await project.start();
  return project;
}

function form(url: string, body: Record<string, string>) {
  return fetch(url, { method: "POST", body: new URLSearchParams(body), redirect: "manual" });
}

async function signIn(base: string, email: string) {
  const authorized = await form(`${base}/o/oauth2/v2/auth/callback`, {
    email,
    client_id: CLIENT.client_id,
    redirect_uri: CLIENT.redirect_uris[0],
    scope: "https://www.googleapis.com/auth/gmail.modify",
  });
  const code = new URL(authorized.headers.get("Location")!).searchParams.get("code")!;
  const token = await form(`${base}/oauth2/token`, {
    code,
    grant_type: "authorization_code",
    client_id: CLIENT.client_id,
    client_secret: CLIENT.client_secret,
    redirect_uri: CLIENT.redirect_uris[0],
  });
  return (await token.json()) as { access_token: string; refresh_token: string };
}

describe("built-in service persistence", () => {
  it("restores saved state and issued tokens instead of seeding", async () => {
    const dir = await project();
    const port = await freePort();
    const base = `http://127.0.0.1:${port}`;
    const first = await run(await writeConfig(dir, port, ["ada@example.com"]));
    let token: { access_token: string; refresh_token: string };
    try {
      token = await signIn(base, "ada@example.com");
      const raw = Buffer.from("To: ada@example.com\r\nSubject: kept\r\n\r\nBody").toString("base64url");
      const sent = await fetch(`${base}/gmail/v1/users/me/messages/send`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token.access_token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ raw }),
      });
      expect(sent.status).toBe(200);
    } finally {
      await first.close();
    }

    // The seed changed meanwhile: the saved state wins.
    const second = await run(await writeConfig(dir, port, ["ada@example.com", "grace@example.com"]));
    try {
      const listed = await fetch(`${base}/gmail/v1/users/me/messages`, {
        headers: { Authorization: `Bearer ${token.access_token}` },
      });
      expect(listed.status).toBe(200);
      expect(((await listed.json()) as { messages?: unknown[] }).messages).toHaveLength(1);
      const renewed = await form(`${base}/oauth2/token`, {
        grant_type: "refresh_token",
        refresh_token: token.refresh_token,
        client_id: CLIENT.client_id,
        client_secret: CLIENT.client_secret,
      });
      expect(renewed.status).toBe(200);
      const page = await fetch(
        `${base}/o/oauth2/v2/auth?client_id=${CLIENT.client_id}&redirect_uri=${encodeURIComponent(CLIENT.redirect_uris[0])}&response_type=code&scope=openid`,
      );
      const html = await page.text();
      expect(html).toContain("ada@example.com");
      expect(html).not.toContain("grace@example.com");
    } finally {
      await second.close();
    }
  });

  it("saves the seeded state once listening and the final state on close", async () => {
    const dir = await project();
    const port = await freePort();
    const state = join(dir, "state/google.json");
    const running = await run(await writeConfig(dir, port, ["ada@example.com"]));
    try {
      const saved = JSON.parse(await readFile(state, "utf8"));
      expect(saved).toMatchObject({ formatVersion: 1, emulator: "google" });
      expect(saved.store.collections["google.users"].items.map((user: { email: string }) => user.email)).toContain(
        "ada@example.com",
      );
      await signIn(`http://127.0.0.1:${port}`, "ada@example.com");
    } finally {
      await running.close();
    }
    const saved = JSON.parse(await readFile(state, "utf8"));
    expect(saved.tokens.length).toBeGreaterThan(0);
  });

  it("leaves saved state unchanged when a listener cannot start", async () => {
    const dir = await project();
    const blocker = createServer();
    await new Promise<void>((done) => blocker.listen(0, "127.0.0.1", done));
    const port = (blocker.address() as { port: number }).port;
    const state = join(dir, "google.json");
    const snapshot = JSON.stringify({
      formatVersion: 1,
      emulator: "google",
      store: { collections: {}, data: {} },
      tokens: [],
    });
    await writeFile(state, snapshot);
    const project_ = await prepareProject({
      port: 4000,
      host: "127.0.0.1",
      config: await writeConfig(dir, port, ["ada@example.com"], "./google.json"),
    });
    try {
      await expect(project_.start()).rejects.toThrow(`Cannot listen for google on port ${port}`);
      expect(await readFile(state, "utf8")).toBe(snapshot);
    } finally {
      await project_.close();
      await new Promise<void>((done) => blocker.close(() => done()));
    }
  });

  it("refuses saved state from another emulator or format", async () => {
    const dir = await project();
    const port = await freePort();
    const config = await writeConfig(dir, port, ["ada@example.com"], "./google.json");
    await writeFile(
      join(dir, "google.json"),
      JSON.stringify({ formatVersion: 1, emulator: "github", store: { collections: {}, data: {} }, tokens: [] }),
    );
    await expect(prepareProject({ port: 4000, config })).rejects.toThrow(
      "Saved state belongs to the github emulator, not google",
    );
    await writeFile(join(dir, "google.json"), JSON.stringify({ state: {} }));
    await expect(prepareProject({ port: 4000, config })).rejects.toThrow("is not a built-in snapshot");
  });

  it("resets to the seed on reload", async () => {
    const dir = await project();
    const port = await freePort();
    const config = await writeConfig(dir, port, ["ada@example.com"]);
    const first = await run(config);
    await first.close();
    await writeConfig(dir, port, ["grace@example.com"]);
    const reloaded = await prepareProject({ port: 4000, host: "127.0.0.1", config }, {}, true);
    await reloaded.start();
    try {
      const page = await fetch(
        `http://127.0.0.1:${port}/o/oauth2/v2/auth?client_id=${CLIENT.client_id}&redirect_uri=${encodeURIComponent(CLIENT.redirect_uris[0])}&response_type=code&scope=openid`,
      );
      expect(await page.text()).toContain("grace@example.com");
    } finally {
      await reloaded.close();
    }
  });

  it("accepts persistence on built-ins and still rejects the inspector", async () => {
    const dir = await project();
    const path = join(dir, "emulate.config.json");
    await writeFile(path, JSON.stringify({ services: { google: { emulator: "google", persistence: "./g.json" } } }));
    const config = await loadConfig({ config: path });
    expect(config.services[0].persistence).toBe(join(dir, "g.json"));
    config.loader.close();
    await writeFile(path, JSON.stringify({ services: { google: { emulator: "google", inspector: true } } }));
    await expect(loadConfig({ config: path })).rejects.toThrow("the inspector option applies to custom APIs");
  });
  it("saves a seed file's service with --persistence", async () => {
    const dir = await project();
    const port = await freePort();
    const seed = join(dir, "seed.json");
    const users = [{ email: "ada@example.com" }];
    await writeFile(seed, JSON.stringify({ google: { port, strict_scopes: true, users, oauth_clients: [CLIENT] } }));
    const options = { port: 4000, host: "127.0.0.1", seed, service: "google", persistence: join(dir, "google.json") };
    const first = await prepareProject(options);
    await first.start();
    let token: { access_token: string };
    try {
      token = await signIn(`http://127.0.0.1:${port}`, "ada@example.com");
    } finally {
      await first.close();
    }
    const second = await prepareProject(options);
    await second.start();
    try {
      const profile = await fetch(`http://127.0.0.1:${port}/gmail/v1/users/me/labels`, {
        headers: { Authorization: `Bearer ${token.access_token}` },
      });
      expect(profile.status).toBe(200);
    } finally {
      await second.close();
    }
    await expect(loadConfig({ seed, service: "google,github", persistence: join(dir, "google.json") })).rejects.toThrow(
      "--persistence saves one service's state",
    );
  });
  it("saves a burst of changes once, after the responses, and everything on close", async () => {
    const dir = await project();
    const port = await freePort();
    const config = join(dir, "emulate.config.mjs");
    const seed = { strict_scopes: true, users: [{ email: "ada@example.com" }], oauth_clients: [CLIENT] };
    await writeFile(
      config,
      `const saves = (globalThis.__builtinPersistenceSaves = []);
export default { services: { google: { emulator: "google", port: ${port}, seed: ${JSON.stringify(seed)},
  persistence: { load: async () => null, save: async (data) => { saves.push(data); } } } } };`,
    );
    const running = await run(config);
    const saves = (globalThis as { __builtinPersistenceSaves?: string[] }).__builtinPersistenceSaves!;
    // The state saved once listening.
    expect(saves).toHaveLength(1);
    try {
      const base = `http://127.0.0.1:${port}`;
      const token = await signIn(base, "ada@example.com");
      for (let i = 0; i < 10; i++) {
        const raw = Buffer.from(`To: ada@example.com\r\nSubject: burst ${i}\r\n\r\nBody`).toString("base64url");
        const sent = await fetch(`${base}/gmail/v1/users/me/messages/send`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token.access_token}`, "Content-Type": "application/json" },
          body: JSON.stringify({ raw }),
        });
        expect(sent.status).toBe(200);
      }
      // Eleven changes answered: at most one save started meanwhile, at the interval.
      expect(saves.length).toBeLessThanOrEqual(2);
    } finally {
      await running.close();
    }
    // The close writes the last change.
    expect(JSON.parse(saves.at(-1)!).store.collections["google.messages"].items.length).toBeGreaterThanOrEqual(10);
    expect(saves.length).toBeLessThanOrEqual(3);
  });
});
