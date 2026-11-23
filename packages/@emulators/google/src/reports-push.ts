import { createHash } from "node:crypto";
import type { Store } from "@emulators/core";
import type { GoogleActivity, GoogleReportsChannel } from "./entities.js";
import { activityResource, onActivity } from "./reports.js";
import { getGoogleStore } from "./store.js";

// Push notifications of the Reports API (https://developers.google.com/workspace/admin/reports/v1/guides/push):
// channels made with activities.watch, the messages sent to their address, and channels.stop.

// "For the Admin SDK API, the maximum expiration time is 21600 seconds. If you don't set the expiration property in
// your request, the expiration time defaults to 21600 seconds after the current time."
export const MAX_CHANNEL_LIFETIME_MS = 21600 * 1000;

// Push messages are sent by the `APIs-Google` user agent
// (https://developers.google.com/crawling/docs/crawlers-fetchers/google-user-triggered-fetchers).
const USER_AGENT = "APIs-Google; (+https://developers.google.com/webmasters/APIs-Google.html)";

// Google asks receivers to answer "within seconds" and does not say when it gives up; the emulator waits this long.
const TIMEOUT_MS = 10_000;

/**
 * "The `resourceId` property is a stable, version-independent identifier for the resource": channels watching the
 * same resource share it.
 */
export function channelResourceId(resourceUri: string): string {
  return createHash("sha256").update(resourceUri).digest("base64url").slice(0, 27);
}

/** The channel as watch returns it: "the properties you sent", plus `resourceId` and `resourceUri`. */
export function channelResource(channel: GoogleReportsChannel): Record<string, unknown> {
  return {
    kind: "api#channel",
    id: channel.channel_id,
    resourceId: channel.resource_id,
    resourceUri: channel.resource_uri,
    ...(channel.token !== null ? { token: channel.token } : {}),
    // "Date and time of notification channel expiration, expressed as a Unix timestamp, in milliseconds", an int64.
    expiration: String(channel.expiration),
  };
}

async function send(channel: GoogleReportsChannel, state: string, number: number, body?: string): Promise<void> {
  const headers: Record<string, string> = {
    "User-Agent": USER_AGENT,
    "X-Goog-Channel-ID": channel.channel_id,
    "X-Goog-Channel-Expiration": new Date(channel.expiration).toUTCString(),
    "X-Goog-Resource-ID": channel.resource_id,
    "X-Goog-Resource-URI": channel.resource_uri,
    "X-Goog-Resource-State": state,
    "X-Goog-Message-Number": String(number),
    ...(channel.token !== null ? { "X-Goog-Channel-Token": channel.token } : {}),
    // The content type of the guide's notification examples.
    ...(body !== undefined ? { "Content-Type": "application/json; utf-8" } : {}),
  };
  try {
    await fetch(channel.address, { method: "POST", headers, body, signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch {
    // "Notifications are not 100% reliable": a message that cannot be delivered is dropped. Google retries some
    // failures on a schedule it does not document; the emulator does not retry.
  }
}

/** "After creating a notification channel to watch a resource, the Admin SDK API sends a `sync` message." */
export function sendSync(channel: GoogleReportsChannel): void {
  setTimeout(() => void send(channel, "sync", 1), 0);
}

/**
 * Sends each activity recorded in `store` to the channels whose watch request it matches, until they expire or are
 * stopped. The body is the activity as activities.list returns it, and `X-Goog-Resource-State` its event name. Google
 * does not document an activity with several events or a channel with `payload: false`: the emulator sends one message
 * per activity, named by the watched (or first) event, and always with its body.
 */
export function startChannelDelivery(
  store: Store,
  matches: (activity: GoogleActivity, channel: GoogleReportsChannel) => boolean,
): void {
  const channels = getGoogleStore(store).reportsChannels;
  onActivity(store, (activity) => {
    const now = Date.now();
    for (const channel of channels.all()) {
      if (channel.application_name !== activity.application_name) continue;
      if (channel.expiration <= now) {
        channels.delete(channel.id);
        continue;
      }
      if (!matches(activity, channel)) continue;
      // "Message numbers increase for each subsequent message on the channel, but they're not sequential."
      const number = channel.message_number + 1;
      channels.update(channel.id, { message_number: number });
      const event = activity.events.find((e) => !channel.event_name || e.name === channel.event_name);
      const body = JSON.stringify(activityResource(store, activity));
      setTimeout(() => void send(channel, event?.name ?? activity.events[0].name, number, body), 0);
    }
  });
}
