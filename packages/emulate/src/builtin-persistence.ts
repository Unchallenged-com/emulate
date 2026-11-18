import {
  filePersistence,
  restoreTokenMap,
  serializeTokenMap,
  type PersistenceAdapter,
  type Store,
  type StoreSnapshot,
  type TokenEntry,
  type TokenMap,
} from "@emulators/core";

const FORMAT_VERSION = 1;
const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

interface BuiltinSnapshot {
  formatVersion: typeof FORMAT_VERSION;
  emulator: string;
  store: StoreSnapshot;
  tokens: TokenEntry[];
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

function parseSnapshot(raw: string, emulator: string): BuiltinSnapshot {
  let snapshot: unknown;
  try {
    snapshot = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Saved ${emulator} state is not valid JSON. Repair or remove the saved snapshot.`, {
      cause: error,
    });
  }
  if (
    !isRecord(snapshot) ||
    snapshot.formatVersion !== FORMAT_VERSION ||
    !isRecord(snapshot.store) ||
    !isRecord(snapshot.store.collections) ||
    !isRecord(snapshot.store.data) ||
    !Array.isArray(snapshot.tokens)
  )
    throw new Error(`Saved ${emulator} state is not a built-in snapshot. Repair or remove the saved snapshot.`);
  if (snapshot.emulator !== emulator)
    throw new Error(
      `Saved state belongs to the ${String(snapshot.emulator)} emulator, not ${emulator}. Choose another persistence file.`,
    );
  return snapshot as unknown as BuiltinSnapshot;
}

/**
 * Saves and restores a built-in service's store and tokens. State is saved after each completed mutating request and
 * when the service closes; saves never overlap, and requests completed during a save are covered by one more save.
 */
export function builtinPersistence(
  persistence: PersistenceAdapter | string,
  emulator: string,
  runtime: { store: Store; tokenMap: TokenMap },
) {
  const adapter = typeof persistence === "string" ? filePersistence(persistence) : persistence;
  let saving: Promise<void> | undefined;
  let again = false;
  let enabled = false;

  function snapshot(): string {
    return JSON.stringify({
      formatVersion: FORMAT_VERSION,
      emulator,
      store: runtime.store.snapshot(),
      tokens: serializeTokenMap(runtime.tokenMap),
    } satisfies BuiltinSnapshot);
  }

  function save(): Promise<void> {
    if (!enabled) return Promise.resolve();
    if (saving) {
      again = true;
      return saving;
    }
    saving = (async () => {
      try {
        do {
          again = false;
          await adapter.save(snapshot());
        } while (again);
      } finally {
        saving = undefined;
      }
    })();
    return saving;
  }

  return {
    /** Restores the saved state. Returns false when nothing was saved yet, so the caller seeds the service. */
    async restore(): Promise<boolean> {
      const raw = await adapter.load();
      if (raw === null) return false;
      const saved = parseSnapshot(raw, emulator);
      runtime.store.restore(saved.store);
      restoreTokenMap(runtime.tokenMap, saved.tokens);
      return true;
    },
    /** Starts saving, first writing the current state, so that a seeded service is saved before its first request. */
    async enable(): Promise<void> {
      enabled = true;
      await save();
    },
    fetch(handler: (request: Request) => Response | Promise<Response>) {
      return async (request: Request): Promise<Response> => {
        const response = await handler(request);
        if (MUTATING_METHODS.has(request.method))
          save().catch((error) => console.error(`Could not save ${emulator} state:`, error));
        return response;
      };
    },
    /** Waits for pending saves and writes the final state. Call before the store is reset. */
    async close(): Promise<void> {
      if (!enabled) return;
      await saving?.catch(() => undefined);
      await save();
      enabled = false;
    },
  };
}
