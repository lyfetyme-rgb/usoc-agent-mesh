import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("firebase-functions/v2/scheduler", () => ({
  onSchedule: (_options: any, handler: any) => handler,
}));

const NOW = 1_700_000_000_000;

vi.mock("../src/lib/firestore", async () => {
  const { FakeFirestore, fakePaths, fakeTimestamp } = await import("./helpers/fakeFirestore");
  return {
    db: new FakeFirestore(),
    auth: { verifyIdToken: vi.fn() },
    paths: fakePaths,
    now: () => fakeTimestamp(NOW),
    Timestamp: {
      now: () => fakeTimestamp(NOW),
      fromMillis: (ms: number) => fakeTimestamp(ms),
    },
    FieldValue: { delete: () => ({ __fakeDelete: true }) },
  };
});

import { db } from "../src/lib/firestore";
import { checkGatewayHeartbeats } from "../src/functions/checkGatewayHeartbeats";

function gateway(status: string, lastSeenAt?: number): any {
  const doc: any = { model: "ROK-01", status, criticalLimits: {} };
  if (lastSeenAt !== undefined) doc.lastSeenAt = { toMillis: () => lastSeenAt };
  return doc;
}

beforeEach(() => {
  (db as any).store.clear();
  (db as any).batches.length = 0;
  const store = (db as any).store as Map<string, any>;
  store.set("tenants/t1/gateways/stale", gateway("ONLINE", NOW - 200_000));
  store.set("tenants/t1/gateways/fresh", gateway("ONLINE", NOW - 100_000));
  store.set("tenants/t1/gateways/never-seen", gateway("PROVISIONING"));
  store.set("tenants/t1/gateways/revoked", gateway("REVOKED", NOW - 500_000));
});

describe("checkGatewayHeartbeats", () => {
  it("flips only gateways silent for more than 180s and raises one alert", async () => {
    await (checkGatewayHeartbeats as any)();

    const store = (db as any).store as Map<string, any>;
    expect(store.get("tenants/t1/gateways/stale")).toMatchObject({ status: "OFFLINE" });
    expect(store.get("tenants/t1/gateways/stale").offlineSince.toMillis()).toBe(NOW);
    expect(store.get("alerts/connectivity_stale")).toMatchObject({
      kind: "CONNECTIVITY",
      status: "OPEN",
      gatewayId: "stale",
    });
    expect(store.get("alerts/connectivity_stale").message).toMatch(/3\+ min/);

    expect(store.get("tenants/t1/gateways/fresh").status).toBe("ONLINE");
    expect(store.get("tenants/t1/gateways/never-seen").status).toBe("PROVISIONING");
    expect(store.get("tenants/t1/gateways/revoked").status).toBe("REVOKED");
    expect(store.has("alerts/connectivity_fresh")).toBe(false);
    expect(store.has("alerts/connectivity_revoked")).toBe(false);
  });

  it("does not emit duplicate alerts on subsequent runs", async () => {
    await (checkGatewayHeartbeats as any)();
    const store = (db as any).store as Map<string, any>;
    const createdAt = store.get("alerts/connectivity_stale").createdAt;

    await (checkGatewayHeartbeats as any)();

    expect(store.get("alerts/connectivity_stale").createdAt).toBe(createdAt);
    expect(store.get("tenants/t1/gateways/stale").status).toBe("OFFLINE");
  });

  it("ignores gateways that are already OFFLINE, even with an old lastSeenAt", async () => {
    const store = (db as any).store as Map<string, any>;
    store.set("tenants/t1/gateways/already-down", gateway("OFFLINE", NOW - 900_000));

    await (checkGatewayHeartbeats as any)();

    expect(store.has("alerts/connectivity_already-down")).toBe(false);
    expect(store.get("tenants/t1/gateways/already-down").offlineSince).toBeUndefined();
  });

  it("flips a large outage without exceeding the 500-operation batch limit", async () => {
    const store = (db as any).store as Map<string, any>;
    for (let i = 0; i < 600; i += 1) {
      store.set(`tenants/t1/gateways/bulk-${i}`, gateway("ONLINE", NOW - 200_000));
    }

    await (checkGatewayHeartbeats as any)();

    const flipped = [...store.entries()].filter(
      ([path, doc]) => path.includes("/gateways/bulk-") && (doc as any).status === "OFFLINE",
    );
    // This assertion counts only the bulk gateways; the seeded "stale" fixture
    // is also flipped and is included in the batch-operation total below.
    expect(flipped).toHaveLength(600);
    expect([...store.keys()].filter((path) => path.startsWith("alerts/connectivity_bulk-"))).toHaveLength(600);

    const batches = (db as any).batches as Array<{ opCount: number }>;
    expect(batches.length).toBeGreaterThan(1);
    expect(Math.max(...batches.map((b) => b.opCount))).toBeLessThanOrEqual(500);
    expect(batches.reduce((sum, b) => sum + b.opCount, 0)).toBe(1_202);
  });
});
