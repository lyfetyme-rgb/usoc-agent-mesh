import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { hourKey } from "../src/lib/rollups";

vi.mock("firebase-functions/v2/https", () => ({ onRequest: (handler: any) => handler }));

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
import { ingestGatewayTelemetry } from "../src/functions/ingestGatewayTelemetry";

const RAW_TOKEN = "device-token";
const TOKEN_HASH = createHash("sha256").update(RAW_TOKEN).digest("hex");
const HEADERS = { "x-gateway-id": "gw1", "x-gateway-token": RAW_TOKEN };
const ROLLUP_PATH = `tenants/t1/gateways/gw1/rollups/${hourKey(NOW)}`;

function seed(status = "ONLINE", criticalLimits: any = { temp: { max: 80 } }): void {
  const store = (db as any).store as Map<string, any>;
  store.set(`gatewayTokens/${TOKEN_HASH}`, {
    tenantId: "t1",
    gatewayId: "gw1",
    createdAt: { toMillis: () => NOW },
  });
  store.set(`tenants/t1/gateways/gw1`, {
    model: "ROK-01",
    tokenHash: TOKEN_HASH,
    status,
    criticalLimits,
    createdAt: { toMillis: () => NOW },
  });
}

function req(body: any, headers = HEADERS, method = "POST"): any {
  return {
    method,
    headers,
    rawBody: Buffer.isBuffer(body) ? body : Buffer.from(JSON.stringify(body)),
    on: () => undefined,
    destroy: () => undefined,
  };
}

function res(): any {
  return {
    statusCode: 200,
    body: undefined,
    headers: {},
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(body: any) {
      this.body = body;
      return this;
    },
    set(key: string, value: string) {
      this.headers[key] = value;
      return this;
    },
    end() {
      return this;
    },
  };
}

beforeEach(() => {
  (db as any).store.clear();
});

describe("ingestGatewayTelemetry", () => {
  it("accepts a valid packet, applies the 30-day TTL and opens a breach alert", async () => {
    seed();
    const response = res();
    await (ingestGatewayTelemetry as any)(req({ temp: 85, vibration: 2 }), response);

    expect(response.statusCode).toBe(204);
    const store = (db as any).store as Map<string, any>;
    const packetEntry = [...store.entries()].find(([path]) => path.includes("/packets/"));
    expect(packetEntry).toBeDefined();
    expect(packetEntry![1]).toMatchObject({
      tenantId: "t1",
      gatewayId: "gw1",
      readings: { temp: 85, vibration: 2 },
      breachCount: 1,
    });
    expect(packetEntry![1].expireAt.toMillis()).toBe(NOW + 30 * 24 * 60 * 60 * 1000);
    expect(store.get(ROLLUP_PATH)).toMatchObject({
      min: 2,
      max: 85,
      breachCount: 1,
      sampleCount: 1,
    });
    expect(store.get("alerts/breach_gw1_temp")).toMatchObject({
      kind: "CRITICAL_LIMIT",
      status: "OPEN",
      value: 85,
    });
    expect(store.get("tenants/t1/gateways/gw1")).toMatchObject({ status: "ONLINE" });
    expect(store.get(`gatewayTokens/${TOKEN_HASH}`).activatedAt.toMillis()).toBe(NOW);
  });

  it("atomically folds later packets into the same hourly rollup", async () => {
    seed();
    await (ingestGatewayTelemetry as any)(req({ temp: 85, vibration: 2 }), res());
    await (ingestGatewayTelemetry as any)(req({ temp: 70, vibration: 4 }), res());
    await (ingestGatewayTelemetry as any)(req({ temp: 90, vibration: 1 }), res());

    const rollup = (db as any).store.get(ROLLUP_PATH);
    expect(rollup).toMatchObject({ min: 1, max: 90, breachCount: 2, sampleCount: 3 });
  });

  it("clears a breach alert when the metric returns to range", async () => {
    seed();
    await (ingestGatewayTelemetry as any)(req({ temp: 85 }), res());
    expect((db as any).store.has("alerts/breach_gw1_temp")).toBe(true);

    await (ingestGatewayTelemetry as any)(req({ temp: 70 }), res());
    expect((db as any).store.has("alerts/breach_gw1_temp")).toBe(false);
  });

  it("marks the gateway back ONLINE and clears the offline alert on recovery", async () => {
    seed("OFFLINE");
    (db as any).store.set("alerts/connectivity_gw1", { kind: "CONNECTIVITY", status: "OPEN" });
    (db as any).store.get("tenants/t1/gateways/gw1").offlineSince = { toMillis: () => NOW - 200_000 };

    await (ingestGatewayTelemetry as any)(req({ temp: 70 }), res());

    const gateway = (db as any).store.get("tenants/t1/gateways/gw1");
    expect(gateway.status).toBe("ONLINE");
    expect(gateway.offlineSince).toBeUndefined();
    expect((db as any).store.has("alerts/connectivity_gw1")).toBe(false);
  });

  it("rejects bad methods, bad credentials and non-numeric or oversized payloads", async () => {
    seed();
    const cases: Array<[any, any, number]> = [
      [req({ temp: 1 }, HEADERS, "GET"), res(), 405],
      [req({ temp: 1 }, { ...HEADERS, "x-gateway-token": "wrong" }), res(), 401],
      [req({ temp: 1 }, { "x-gateway-id": "gw1" }), res(), 401],
      [req({ temp: "1" }), res(), 400],
      [req(Buffer.alloc(4096)), res(), 413],
    ];
    for (const [request, response, expected] of cases) {
      await (ingestGatewayTelemetry as any)(request, response);
      expect(response.statusCode).toBe(expected);
    }
  });
});
