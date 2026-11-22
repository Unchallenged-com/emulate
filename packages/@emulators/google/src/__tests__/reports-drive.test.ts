import { describe, expect, it } from "vitest";
import {
  Hono,
  Store,
  WebhookDispatcher,
  authMiddleware,
  setClientAddress,
  type AppEnv,
  type TokenMap,
} from "@emulators/core";
import { googlePlugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";
const driveReport = "/admin/reports/v1/activity/users/all/applications/drive";
const admin = "admin@example.com";
const staff = "staff@example.com";
const staffIp = "198.51.100.8";
const auditScope = "https://www.googleapis.com/auth/admin.reports.audit.readonly";
const driveScope = "https://www.googleapis.com/auth/drive";
const client = {
  client_id: "drive-app",
  client_secret: "drive-secret",
  redirect: "https://drive.example.net/callback",
};

type Parameter = { name: string; value?: string; boolValue?: boolean };
type Activity = {
  actor: Record<string, unknown>;
  ipAddress?: string;
  events: Array<{ type: string; name: string; parameters: Parameter[] }>;
};

async function fixture() {
  const app = new Hono<AppEnv>();
  const store = new Store();
  const tokens: TokenMap = new Map();
  app.use("*", authMiddleware(tokens, undefined, { login: admin, id: 1, scopes: [] }));
  googlePlugin.register(app, store, new WebhookDispatcher(), base, tokens);
  googlePlugin.seed?.(store, base);
  seedFromConfig(store, base, {
    strict_scopes: true,
    users: [
      { email: admin, name: "Ada Admin", is_admin: true },
      { email: staff, name: "Sam Staff" },
    ],
    oauth_clients: [{ ...client, name: "Drive app", redirect_uris: [client.redirect] }],
  });

  const send = (path: string, init: RequestInit = {}, token?: string, contentType = "application/json") => {
    const request = new Request(`${base}${path}`, {
      ...init,
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), "Content-Type": contentType },
    });
    setClientAddress(request, staffIp);
    return app.fetch(request);
  };
  async function grant(email: string, scope: string) {
    const form = "application/x-www-form-urlencoded";
    const authorize = await send(
      "/o/oauth2/v2/auth/callback",
      {
        method: "POST",
        body: new URLSearchParams({ email, redirect_uri: client.redirect, scope, client_id: client.client_id }),
      },
      undefined,
      form,
    );
    const code = new URL(authorize.headers.get("Location")!).searchParams.get("code")!;
    const exchange = await send(
      "/oauth2/token",
      {
        method: "POST",
        body: new URLSearchParams({
          client_id: client.client_id,
          client_secret: client.client_secret,
          grant_type: "authorization_code",
          code,
          redirect_uri: client.redirect,
        }),
      },
      undefined,
      form,
    );
    return ((await exchange.json()) as { access_token: string }).access_token;
  }
  const staffToken = await grant(staff, driveScope);
  const adminToken = await grant(admin, auditScope);
  const drive = (path: string, method = "GET", body?: unknown) =>
    send(path, { method, ...(body ? { body: JSON.stringify(body) } : {}) }, staffToken);
  const upload = (name: string, content: string) => {
    const boundary = "b1";
    const body = [
      `--${boundary}`,
      "Content-Type: application/json; charset=UTF-8",
      "",
      JSON.stringify({ name }),
      `--${boundary}`,
      "Content-Type: application/pdf",
      "",
      content,
      `--${boundary}--`,
      "",
    ].join("\r\n");
    return send(
      "/upload/drive/v3/files?uploadType=multipart",
      { method: "POST", body },
      staffToken,
      `multipart/related; boundary=${boundary}`,
    );
  };

  /** The Drive activities, oldest first. */
  async function report(query = ""): Promise<Activity[]> {
    const response = await send(`${driveReport}${query}`, {}, adminToken);
    expect(response.status).toBe(200);
    return (((await response.json()) as { items?: Activity[] }).items ?? []).reverse();
  }
  return { drive, upload, report };
}

const value = (activity: Activity, name: string) => {
  const parameter = activity.events[0].parameters.find((p) => p.name === name);
  return parameter?.value ?? parameter?.boolValue;
};

describe("Google Reports API Drive events", () => {
  it("records an uploaded file with Drive's access parameters, in the order of recorded activities", async () => {
    const { upload, report } = await fixture();
    const uploaded = await upload("invoice.pdf", "%PDF-1.4");
    expect(uploaded.status).toBe(200);
    const { id } = (await uploaded.json()) as { id: string };

    const [activity] = await report();
    expect(activity.actor).toEqual({ email: staff, profileId: expect.any(String) });
    expect(activity.ipAddress).toBe(staffIp);
    expect(activity.events[0]).toMatchObject({
      type: "access",
      name: "upload",
      parameters: [
        { name: "primary_event", boolValue: true },
        { name: "billable", boolValue: true },
        { name: "owner_is_shared_drive", boolValue: false },
        { name: "owner", value: staff },
        { name: "doc_id", value: id },
        { name: "doc_type", value: "pdf" },
        { name: "is_encrypted", boolValue: false },
        { name: "doc_title", value: "invoice.pdf" },
        { name: "visibility", value: "private" },
        { name: "actor_is_collaborator_account", boolValue: false },
        { name: "owner_is_team_drive", boolValue: false },
      ],
    });
    expect((activity.events[0] as { resourceIds?: string[] }).resourceIds).toEqual([id]);
    expect((activity as Activity & { resourceDetails?: unknown }).resourceDetails).toEqual([
      { id, title: "invoice.pdf", type: "DRIVE_ITEM", relation: "DRIVE_PRIMARY" },
    ]);
  });

  it("records creations, content reads by the application, renames and moves", async () => {
    const { drive, upload, report } = await fixture();
    const folder = (await (
      await drive("/drive/v3/files", "POST", { name: "Finance", mimeType: "application/vnd.google-apps.folder" })
    ).json()) as { id: string };
    const file = (await (await upload("invoice.pdf", "%PDF-1.4")).json()) as { id: string };
    expect((await drive(`/drive/v3/files/${file.id}?alt=media`)).status).toBe(200);
    expect((await drive(`/drive/v3/files/${file.id}`)).status).toBe(200);
    expect((await drive("/drive/v3/files")).status).toBe(200);
    expect((await drive(`/drive/v3/files/${file.id}`, "PATCH", { name: "invoice-2026.pdf" })).status).toBe(200);
    expect(
      (await drive(`/drive/v3/files/${file.id}?addParents=${folder.id}&removeParents=root`, "PATCH", {})).status,
    ).toBe(200);

    const activities = await report();
    // Metadata reads and lists leave nothing.
    expect(activities.map((activity) => activity.events[0].name)).toEqual([
      "create",
      "upload",
      "access_item_content",
      "rename",
      "move",
    ]);
    const [created, , read, renamed, moved] = activities;
    expect(value(created, "doc_type")).toBe("folder");
    expect(value(read, "api_method")).toBe("drive.files.get");
    expect(value(renamed, "old_value")).toBe("invoice.pdf");
    expect(value(renamed, "new_value")).toBe("invoice-2026.pdf");
    expect(value(renamed, "doc_title")).toBe("invoice-2026.pdf");
    expect(value(moved, "source_folder_id")).toBe("root");
    expect(value(moved, "destination_folder_id")).toBe(folder.id);
    expect(value(moved, "destination_folder_title")).toBe("Finance");
  });

  it("records nothing for an unknown file", async () => {
    const { drive, report } = await fixture();
    expect((await drive("/drive/v3/files/nope?alt=media")).status).toBe(404);
    expect(await report()).toEqual([]);
  });
});
