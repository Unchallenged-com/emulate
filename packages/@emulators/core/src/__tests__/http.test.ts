import { describe, expect, it } from "vitest";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { Hono, clientAddress, cors, serve } from "../http.js";

describe("HTTP listener", () => {
  it.each([
    { hostname: undefined, address: "127.0.0.1" },
    { hostname: "0.0.0.0", address: "0.0.0.0" },
  ])("binds to $address with hostname $hostname", async ({ hostname, address }) => {
    const server = serve({ fetch: () => new Response("ready"), port: 0, hostname });
    try {
      await once(server, "listening");
      const bound = server.address() as AddressInfo;
      expect(bound.address).toBe(address);
      expect(await (await fetch(`http://localhost:${bound.port}`)).text()).toBe("ready");
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeAllConnections();
      });
    }
  });
});

describe("client address", () => {
  async function addressSeen(headers: Record<string, string>, hostname?: string, url = "http://127.0.0.1") {
    const server = serve({
      fetch: (request) => new Response(clientAddress(request) ?? "none"),
      port: 0,
      hostname,
    });
    try {
      await once(server, "listening");
      const { port } = server.address() as AddressInfo;
      return await (await fetch(`${url}:${port}`, { headers })).text();
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeAllConnections();
      });
    }
  }

  it("is the connection's peer", async () => {
    expect(await addressSeen({})).toBe("127.0.0.1");
  });

  it("is the address a proxy on the loopback interface added to X-Forwarded-For", async () => {
    expect(await addressSeen({ "X-Forwarded-For": "203.0.113.9, 198.51.100.7" })).toBe("198.51.100.7");
    expect(await addressSeen({ "X-Forwarded-For": "::ffff:198.51.100.7" })).toBe("198.51.100.7");
  });

  it("ignores X-Forwarded-For from a peer that is not on the loopback interface", async () => {
    const { networkInterfaces } = await import("node:os");
    const external = Object.values(networkInterfaces())
      .flat()
      .find((iface) => iface && iface.family === "IPv4" && !iface.internal)?.address;
    if (!external) return;
    expect(await addressSeen({ "X-Forwarded-For": "198.51.100.7" }, "0.0.0.0", `http://${external}`)).toBe(external);
  });

  it("is unknown for requests that did not come through a listener", async () => {
    const app = new Hono();
    app.get("/", (c) => c.text(clientAddress(c.req.raw) ?? "none"));
    expect(await (await app.request("/", { headers: { "X-Forwarded-For": "198.51.100.7" } })).text()).toBe("none");
  });
});

describe("internal http layer", () => {
  it("dispatches middleware and route handlers with params", async () => {
    const app = new Hono();
    const calls: string[] = [];

    app.use("*", async (c, next) => {
      calls.push(`before:${c.req.method}`);
      c.set("seen", "yes");
      await next();
      calls.push("after");
    });
    app.get("/repos/:owner/:repo/git/ref/:ref{.+}", (c) => {
      calls.push(c.get("seen"));
      return c.json({
        owner: c.req.param("owner"),
        repo: c.req.param("repo"),
        ref: c.req.param("ref"),
      });
    });

    const res = await app.request("/repos/acme/widgets/git/ref/heads/main");

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ owner: "acme", repo: "widgets", ref: "heads/main" });
    expect(calls).toEqual(["before:GET", "yes", "after"]);
  });

  it("respects explicit content type headers", async () => {
    const app = new Hono();
    app.get("/object", (c) => c.text("hello", 200, { "Content-Type": "text/plain" }));

    const res = await app.request("/object");

    expect(res.headers.get("Content-Type")).toBe("text/plain");
  });

  it("prefers explicit HEAD routes over GET fallback", async () => {
    const app = new Hono();
    app.get("/object", (c) => c.text("get", 200, { "X-Handler": "get" }));
    app.on("HEAD", "/object", (c) => c.body(null, 200, { "X-Handler": "head" }));

    const res = await app.request("/object", { method: "HEAD" });

    expect(res.status).toBe(200);
    expect(res.headers.get("X-Handler")).toBe("head");
  });

  it("falls back to GET routes for HEAD requests", async () => {
    const app = new Hono();
    app.get("/object", (c) => c.text("get", 200, { "X-Handler": "get" }));

    const res = await app.request("/object", { method: "HEAD" });

    expect(res.status).toBe(200);
    expect(res.headers.get("X-Handler")).toBe("get");
  });

  it("handles CORS preflight requests", async () => {
    const app = new Hono();
    app.use("*", cors({ allowMethods: ["GET"], allowHeaders: ["x-test"], maxAge: 60 }));
    app.get("/items", (c) => c.json([]));

    const res = await app.request("/items", { method: "OPTIONS" });

    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(res.headers.get("Access-Control-Allow-Methods")).toBe("GET");
    expect(res.headers.get("Access-Control-Allow-Headers")).toBe("x-test");
    expect(res.headers.get("Access-Control-Max-Age")).toBe("60");
  });
});
