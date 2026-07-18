import { describe, expect, test } from "bun:test";
import {
  createMemoryFeedStore,
  emptyFeedCursor,
  isFeedFresh,
  mergeFeedRecords,
  normalizeFeedDescriptor,
  syncFeed,
  type FeedAdapter,
  type FeedSnapshot,
} from "../src";

type Fixture = { value: string };

const timestamp = "2026-07-18T18:30:00Z";
const descriptor = {
  id: "fixture",
  name: "Fixture feed",
  url: "https://security.example/feed",
};
const snapshot = (fetchedAt = timestamp): FeedSnapshot<Fixture> => ({
  cursor: emptyFeedCursor(),
  feed: normalizeFeedDescriptor(descriptor),
  fetchedAt,
  records: [{ id: "CVE-2", modifiedAt: timestamp, value: { value: "cached" } }],
  revision: "1",
});

describe("feed descriptors and records", () => {
  test("normalizes descriptors and requires HTTPS", () => {
    expect(
      normalizeFeedDescriptor({
        id: " fixture ",
        name: " Fixture ",
        url: "https://security.example/feed",
      }),
    ).toEqual({
      id: "fixture",
      name: "Fixture",
      url: "https://security.example/feed",
    });
    expect(() =>
      normalizeFeedDescriptor({ ...descriptor, url: "http://example.test" }),
    ).toThrow("Feed URL must use HTTPS");
  });

  test("merges incrementally, deletes records, and keeps the newest revision", () => {
    const records = mergeFeedRecords({
      current: [
        { id: "CVE-2", modifiedAt: "2026-07-18T10:00:00Z", value: 2 },
        { id: "CVE-1", modifiedAt: "2026-07-18T10:00:00Z", value: 1 },
      ],
      deletedIds: ["CVE-1"],
      incoming: [
        { id: "CVE-2", modifiedAt: "2026-07-18T09:00:00Z", value: 20 },
        { id: "CVE-3", modifiedAt: "2026-07-18T11:00:00Z", value: 3 },
      ],
      replaceAll: false,
    });

    expect(records.map(({ id }) => id)).toEqual(["CVE-2", "CVE-3"]);
    expect(records[0]?.value).toBe(2);
  });

  test("replaces complete snapshots and rejects invalid timestamps", () => {
    expect(
      mergeFeedRecords({
        current: [
          { id: "old", modifiedAt: timestamp, value: { value: "old" } },
        ],
        incoming: [
          { id: "new", modifiedAt: timestamp, value: { value: "new" } },
        ],
        replaceAll: true,
      }).map(({ id }) => id),
    ).toEqual(["new"]);
    expect(() =>
      mergeFeedRecords({
        current: [],
        incoming: [{ id: "bad", modifiedAt: "not-a-date", value: null }],
        replaceAll: true,
      }),
    ).toThrow("valid timestamp");
  });
});

describe("feed synchronization", () => {
  test("saves updated snapshots", async () => {
    const store = createMemoryFeedStore<Fixture>();
    const adapter: FeedAdapter<Fixture> = {
      descriptor,
      fetch: async ({ cursor }) => {
        expect(cursor).toBeNull();
        return {
          cursor: { etag: '"2"', lastModified: null, token: null },
          fetchedAt: timestamp,
          records: [
            { id: "CVE-1", modifiedAt: timestamp, value: { value: "new" } },
          ],
          replaceAll: true,
          revision: "2",
          status: "updated",
        };
      },
    };

    const result = await syncFeed({ adapter, maxStaleMs: 60_000, store });
    expect(result.status).toBe("updated");
    expect(result.snapshot?.records[0]?.id).toBe("CVE-1");
    expect((await store.load("fixture"))?.revision).toBe("2");
  });

  test("accepts not-modified only when a cached snapshot exists", async () => {
    const adapter: FeedAdapter<Fixture> = {
      descriptor,
      fetch: async () => ({ status: "not_modified" }),
    };
    const cached = await syncFeed({
      adapter,
      maxStaleMs: 60_000,
      store: createMemoryFeedStore([snapshot()]),
    });
    const empty = await syncFeed({
      adapter,
      maxStaleMs: 60_000,
      store: createMemoryFeedStore(),
    });

    expect(cached.status).toBe("not_modified");
    expect(cached.snapshot?.revision).toBe("1");
    expect(empty).toEqual({
      error: "Feed returned not_modified without a cached snapshot",
      snapshot: null,
      status: "failed",
    });
  });

  test("preserves cached intelligence and identifies stale failures", async () => {
    const adapter: FeedAdapter<Fixture> = {
      descriptor,
      fetch: async () => {
        throw new Error("provider unavailable");
      },
    };
    const now = Date.parse("2026-07-18T20:30:00Z");
    const fresh = await syncFeed({
      adapter,
      maxStaleMs: 3 * 60 * 60 * 1_000,
      now,
      store: createMemoryFeedStore([snapshot()]),
    });
    const stale = await syncFeed({
      adapter,
      maxStaleMs: 60 * 60 * 1_000,
      now,
      store: createMemoryFeedStore([snapshot()]),
    });

    expect(fresh.status).toBe("failed");
    expect(fresh.snapshot?.records[0]?.value.value).toBe("cached");
    expect(stale.status).toBe("stale");
    expect(stale.error).toBe("provider unavailable");
  });

  test("checks freshness against an explicit clock", () => {
    expect(
      isFeedFresh({
        maxAgeMs: 60_000,
        now: Date.parse("2026-07-18T18:30:30Z"),
        snapshot: snapshot(),
      }),
    ).toBe(true);
    expect(() => isFeedFresh({ maxAgeMs: -1, snapshot: snapshot() })).toThrow(
      "non-negative",
    );
  });
});
