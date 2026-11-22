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
});
