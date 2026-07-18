import { describe, expect, test } from "bun:test";
import {
  createMemoryFeedStore,
  syncFeedRecorded,
  type FeedAdapter,
  type FeedSyncRun,
  type FeedSyncRunStore,
} from "../src";

describe("recorded feed synchronization", () => {
  test("records successful feed provenance and record counts", async () => {
    const runs: FeedSyncRun[] = [];
    const history: FeedSyncRunStore = {
      append: async (run) => {
        runs.push(run);
      },
      list: async () => runs,
    };
    const adapter: FeedAdapter<{ cve: string }> = {
      descriptor: {
        id: "fixture",
        name: "Fixture",
        url: "https://security.example/feed",
      },
      fetch: async () => ({
        cursor: { etag: '"2"', lastModified: null, token: null },
        fetchedAt: "2026-07-18T19:00:01Z",
        records: [
          {
            id: "CVE-2026-0001",
            modifiedAt: "2026-07-18T18:00:00Z",
            value: { cve: "CVE-2026-0001" },
          },
        ],
        replaceAll: true,
        revision: "2",
        status: "updated",
      }),
    };
    const times = [
      new Date("2026-07-18T19:00:00Z"),
      new Date("2026-07-18T19:00:02Z"),
    ];
    const output = await syncFeedRecorded({
      adapter,
      clock: () => times.shift() ?? new Date(0),
      history,
      maxStaleMs: 60_000,
      runId: "run-1",
      store: createMemoryFeedStore(),
    });

    expect(output.result.status).toBe("updated");
    expect(output.run).toEqual({
      completedAt: "2026-07-18T19:00:02.000Z",
      error: null,
      feedId: "fixture",
      id: "run-1",
      records: 1,
      revision: "2",
      startedAt: "2026-07-18T19:00:00.000Z",
      status: "updated",
    });
    expect(await history.list()).toEqual([output.run]);
  });

  test("records isolated provider failures", async () => {
    const runs: FeedSyncRun[] = [];
    const adapter: FeedAdapter<never> = {
      descriptor: {
        id: "failed",
        name: "Failed fixture",
        url: "https://security.example/failed",
      },
      fetch: async () => {
        throw new Error("provider unavailable");
      },
    };
    const output = await syncFeedRecorded({
      adapter,
      history: {
        append: async (run) => {
          runs.push(run);
        },
        list: async () => runs,
      },
      maxStaleMs: 60_000,
      runId: "run-failed",
      store: createMemoryFeedStore(),
    });

    expect(output.result.status).toBe("failed");
    expect(runs[0]?.error).toBe("provider unavailable");
    expect(runs[0]?.records).toBe(0);
  });
});
