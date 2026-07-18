export type FeedDescriptor = {
  id: string;
  name: string;
  url: string;
};

export type FeedCursor = {
  etag: string | null;
  lastModified: string | null;
  token: string | null;
};

export type FeedRecord<T> = {
  id: string;
  modifiedAt: string;
  value: T;
};

export type FeedSnapshot<T> = {
  cursor: FeedCursor;
  feed: FeedDescriptor;
  fetchedAt: string;
  records: FeedRecord<T>[];
  revision: string | null;
};

export type FeedFetchRequest = {
  cursor: FeedCursor | null;
  signal?: AbortSignal;
};

export type FeedFetchResult<T> =
  | { status: "not_modified" }
  | {
      cursor: FeedCursor;
      deletedIds?: string[];
      fetchedAt: string;
      records: FeedRecord<T>[];
      replaceAll: boolean;
      revision: string | null;
      status: "updated";
    };

export type FeedAdapter<T> = {
  descriptor: FeedDescriptor;
  fetch: (request: FeedFetchRequest) => Promise<FeedFetchResult<T>>;
};

export type FeedSnapshotStore<T> = {
  load: (feedId: string) => Promise<FeedSnapshot<T> | null>;
  save: (snapshot: FeedSnapshot<T>) => Promise<void>;
};

export type FeedSyncResult<T> = {
  error: string | null;
  snapshot: FeedSnapshot<T> | null;
  status: "failed" | "not_modified" | "stale" | "updated";
};

export type FeedSyncRun = {
  completedAt: string;
  error: string | null;
  feedId: string;
  id: string;
  records: number;
  revision: string | null;
  startedAt: string;
  status: FeedSyncResult<unknown>["status"];
};

export type FeedSyncRunFilter = {
  feedId?: string;
  limit?: number;
  status?: FeedSyncRun["status"];
};

export type FeedSyncRunStore = {
  append: (run: FeedSyncRun) => Promise<void>;
  list: (filter?: FeedSyncRunFilter) => Promise<FeedSyncRun[]>;
};

const requiredText = (label: string, value: string) => {
  const normalized = value.trim();
  if (normalized.length === 0) throw new Error(`${label} is required`);
  return normalized;
};

export const normalizeFeedDescriptor = (
  descriptor: FeedDescriptor,
): FeedDescriptor => {
  const id = requiredText("Feed id", descriptor.id);
  const name = requiredText("Feed name", descriptor.name);
  let url: URL;
  try {
    url = new URL(descriptor.url);
  } catch {
    throw new Error("Feed URL must be valid");
  }
  if (url.protocol !== "https:") throw new Error("Feed URL must use HTTPS");
  return { id, name, url: url.toString() };
};

export const emptyFeedCursor = (): FeedCursor => ({
  etag: null,
  lastModified: null,
  token: null,
});

export const mergeFeedRecords = <T>(input: {
  current: readonly FeedRecord<T>[];
  deletedIds?: readonly string[];
  incoming: readonly FeedRecord<T>[];
  replaceAll: boolean;
}) => {
  const normalizeRecord = (record: FeedRecord<T>) => {
    const id = requiredText("Feed record id", record.id);
    const modifiedAt = requiredText(
      "Feed record modifiedAt",
      record.modifiedAt,
    );
    if (!Number.isFinite(Date.parse(modifiedAt)))
      throw new Error("Feed record modifiedAt must be a valid timestamp");
    return { ...record, id, modifiedAt };
  };
  const records = new Map<string, FeedRecord<T>>();
  if (!input.replaceAll)
    for (const record of input.current) {
      const normalized = normalizeRecord(record);
      records.set(normalized.id, normalized);
    }
  for (const id of input.deletedIds ?? [])
    records.delete(requiredText("Deleted feed record id", id));
  for (const record of input.incoming) {
    const normalized = normalizeRecord(record);
    const existing = records.get(normalized.id);
    if (
      !existing ||
      Date.parse(existing.modifiedAt) <= Date.parse(normalized.modifiedAt)
    )
      records.set(normalized.id, normalized);
  }
  return [...records.values()].sort((left, right) =>
    left.id.localeCompare(right.id),
  );
};

export const isFeedFresh = (input: {
  maxAgeMs: number;
  now?: number;
  snapshot: FeedSnapshot<unknown>;
}) => {
  if (!Number.isFinite(input.maxAgeMs) || input.maxAgeMs < 0)
    throw new Error("Feed maxAgeMs must be a non-negative finite number");
  const fetchedAt = Date.parse(input.snapshot.fetchedAt);
  if (!Number.isFinite(fetchedAt)) return false;
  return (input.now ?? Date.now()) - fetchedAt <= input.maxAgeMs;
};

export const syncFeed = async <T>(input: {
  adapter: FeedAdapter<T>;
  maxStaleMs: number;
  now?: number;
  signal?: AbortSignal;
  store: FeedSnapshotStore<T>;
}): Promise<FeedSyncResult<T>> => {
  const descriptor = normalizeFeedDescriptor(input.adapter.descriptor);
  const previous = await input.store.load(descriptor.id);
  try {
    const fetched = await input.adapter.fetch({
      cursor: previous?.cursor ?? null,
      ...(input.signal ? { signal: input.signal } : {}),
    });
    if (fetched.status === "not_modified") {
      if (previous === null)
        return {
          error: "Feed returned not_modified without a cached snapshot",
          snapshot: null,
          status: "failed",
        };
      return { error: null, snapshot: previous, status: "not_modified" };
    }
    const snapshot: FeedSnapshot<T> = {
      cursor: fetched.cursor,
      feed: descriptor,
      fetchedAt: fetched.fetchedAt,
      records: mergeFeedRecords({
        current: previous?.records ?? [],
        deletedIds: fetched.deletedIds,
        incoming: fetched.records,
        replaceAll: fetched.replaceAll,
      }),
      revision: fetched.revision,
    };
    await input.store.save(snapshot);
    return { error: null, snapshot, status: "updated" };
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unknown feed error";
    if (previous === null)
      return { error: message, snapshot: null, status: "failed" };
    return {
      error: message,
      snapshot: previous,
      status: isFeedFresh({
        maxAgeMs: input.maxStaleMs,
        now: input.now,
        snapshot: previous,
      })
        ? "failed"
        : "stale",
    };
  }
};

export const syncFeedRecorded = async <T>(input: {
  adapter: FeedAdapter<T>;
  clock?: () => Date;
  history: FeedSyncRunStore;
  maxStaleMs: number;
  now?: number;
  runId?: string;
  signal?: AbortSignal;
  store: FeedSnapshotStore<T>;
}) => {
  const clock = input.clock ?? (() => new Date());
  const startedAt = clock().toISOString();
  const result = await syncFeed({
    adapter: input.adapter,
    maxStaleMs: input.maxStaleMs,
    ...(input.now === undefined ? {} : { now: input.now }),
    ...(input.signal ? { signal: input.signal } : {}),
    store: input.store,
  });
  const run: FeedSyncRun = {
    completedAt: clock().toISOString(),
    error: result.error,
    feedId: normalizeFeedDescriptor(input.adapter.descriptor).id,
    id: input.runId ?? crypto.randomUUID(),
    records: result.snapshot?.records.length ?? 0,
    revision: result.snapshot?.revision ?? null,
    startedAt,
    status: result.status,
  };
  await input.history.append(run);
  return { result, run };
};

export const createMemoryFeedStore = <T>(
  initial: readonly FeedSnapshot<T>[] = [],
): FeedSnapshotStore<T> => {
  const snapshots = new Map(
    initial.map((snapshot) => [snapshot.feed.id, structuredClone(snapshot)]),
  );
  return {
    load: async (feedId) => {
      const snapshot = snapshots.get(feedId);
      return snapshot ? structuredClone(snapshot) : null;
    },
    save: async (snapshot) => {
      snapshots.set(snapshot.feed.id, structuredClone(snapshot));
    },
  };
};
