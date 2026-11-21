import type { RouteContext } from "@emulators/core";
import { LogFilterError, matchesLogFilter, parseLogFilter, type LogFilter } from "../log-filter.js";
import { oktaError, requireManagementAuth } from "../route-helpers.js";
import { getOktaStore } from "../store.js";
import type { OktaLogEventEntry } from "../entities.js";

// GET /api/v1/logs, with the semantics of https://developer.okta.com/docs/reference/system-log-query/

const DAY_MS = 24 * 60 * 60 * 1000;
const RETENTION_MS = 90 * DAY_MS;
const MAX_SINCE_AGE_MS = 180 * DAY_MS;
const DEFAULT_WINDOW_MS = 7 * DAY_MS;
const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 1000;
const MAX_KEYWORD_LENGTH = 40;

function parseTime(value: string): number | null {
  // ISO 8601 date-times only: Date.parse alone would also accept forms such as "March 7".
  if (!/^\d{4}-\d{2}-\d{2}(T[\d:.]+(Z|[+-]\d{2}:?\d{2})?)?$/.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

function dateError(name: string) {
  return {
    summary: `Api validation failed: '${name}': The date format in your query is not recognized. Please enter dates using ISO8601 string format. '${name}': must be a valid date-time or empty.`,
    causes: [
      {
        errorSummary: `${name}: The date format in your query is not recognized. Please enter dates using ISO8601 string format.`,
      },
      { errorSummary: `${name}: must be a valid date-time or empty.` },
    ],
  };
}

// The words a keyword search can match in a record: every string or number value, whole, split on spaces, and
// split on hyphens ("events that contain the text XOxBw-2JIRn are matched with a q value of XOxBw").
function keywordsOf(value: unknown, into: Set<string>): Set<string> {
  if (value === null || value === undefined) return into;
  if (typeof value === "string" || typeof value === "number") {
    const text = String(value).toLowerCase();
    into.add(text);
    for (const word of text.split(/\s+/)) {
      into.add(word);
      for (const part of word.split("-")) into.add(part);
    }
  } else if (typeof value === "object") {
    for (const item of Object.values(value)) keywordsOf(item, into);
  }
  return into;
}

function cursorOf(entry: OktaLogEventEntry): string {
  return `${Date.parse(entry.published)}_${entry.id}`;
}

function cursorPosition(after: string): number | null {
  const match = /^\d+_(\d+)$/.exec(after);
  return match ? Number(match[1]) : null;
}

export function logRoutes({ app, store, baseUrl, tokenMap }: RouteContext): void {
  const oktaStore = getOktaStore(store);

  app.get("/api/v1/logs", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;

    const now = Date.now();
    const sinceParam = c.req.query("since");
    const untilParam = c.req.query("until");
    const after = c.req.query("after");
    const filterParam = c.req.query("filter");
    const q = c.req.query("q");
    const descending = (c.req.query("sortOrder") ?? "").toUpperCase() === "DESCENDING";

    let until: number | null = null;
    if (untilParam) {
      until = parseTime(untilParam);
      if (until === null) {
        const error = dateError("until");
        return oktaError(c, 400, "E0000001", error.summary, error.causes);
      }
    }
    let since = (until ?? now) - DEFAULT_WINDOW_MS;
    if (sinceParam) {
      const parsed = parseTime(sinceParam);
      if (parsed === null) {
        const error = dateError("since");
        return oktaError(c, 400, "E0000001", error.summary, error.causes);
      }
      if (now - parsed > MAX_SINCE_AGE_MS) {
        return oktaError(
          c,
          400,
          "E0000053",
          "Invalid parameter: The since parameter is over 180 days prior to the current day.",
        );
      }
      since = parsed;
    }

    const keywords = (q ?? "").split(/\s+/).filter(Boolean);
    if (keywords.some((keyword) => keyword.length > MAX_KEYWORD_LENGTH)) {
      return oktaError(
        c,
        400,
        "E0000001",
        "Api validation failed: 'q': Freeform search cannot contain items longer than 40 characters. Please shorten the items in your search or use an advanced filter to query by specific fields.",
      );
    }

    let filter: LogFilter | null = null;
    if (filterParam) {
      try {
        filter = parseLogFilter(filterParam);
      } catch (error) {
        if (error instanceof LogFilterError) return oktaError(c, 400, error.errorCode, error.message);
        throw error;
      }
    }

    const parsedLimit = Number.parseInt(c.req.query("limit") ?? "", 10);
    const limit = Number.isNaN(parsedLimit) ? DEFAULT_LIMIT : Math.min(MAX_LIMIT, Math.max(0, parsedLimit));

    // A polling request (no `until`, ascending) reads in the order events were recorded and never ends.
    const polling = !untilParam && !descending;
    const position = after ? cursorPosition(after) : null;
    const lowerBound = Math.max(since, now - RETENTION_MS);

    // Collection ids follow the order events were recorded, which is also the order of their `published` times.
    let window = oktaStore.logEvents.all().filter((entry) => {
      const published = Date.parse(entry.published);
      if (published < lowerBound) return false;
      if (until !== null && published >= until) return false;
      return true;
    });
    window.sort((a, b) => a.id - b.id);
    if (descending) window.reverse();
    if (position !== null) {
      window = window.filter((entry) => (descending ? entry.id < position : entry.id > position));
    }

    const lowered = keywords.map((keyword) => keyword.toLowerCase());
    const matching = window.filter((entry) => {
      if (filter && !matchesLogFilter(filter, entry.event)) return false;
      if (lowered.length > 0) {
        const words = keywordsOf(entry.event, new Set());
        if (!lowered.every((keyword) => words.has(keyword))) return false;
      }
      return true;
    });

    const page = matching.slice(0, limit);
    const more = matching.length > page.length;

    const self = new URL(`${baseUrl}/api/v1/logs`);
    for (const [key, value] of new URL(c.req.url).searchParams) self.searchParams.append(key, value);
    c.header("Link", `<${self.toString()}>; rel="self"`, { append: true });

    let nextCursor: string | null = null;
    if (page.length > 0 && (more || polling)) {
      // A polling page that is not full has read everything recorded so far: continue after the last event scanned,
      // so events that did not match are not read again.
      const last = more ? page[page.length - 1]! : (window[window.length - 1] ?? page[page.length - 1]!);
      nextCursor = cursorOf(last);
    } else if (polling) {
      const last = window[window.length - 1];
      nextCursor = last ? cursorOf(last) : (after ?? null);
    }
    if (more || polling) {
      const next = new URL(self.toString());
      if (nextCursor) next.searchParams.set("after", nextCursor);
      c.header("Link", `<${next.toString()}>; rel="next"`, { append: true });
    }

    return c.json(page.map((entry) => entry.event));
  });
}
