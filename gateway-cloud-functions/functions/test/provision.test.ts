import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

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

import { auth, db } from "../src/lib/firestore";
import { provisionTenantAndGateway } from "../src/functions/provisionTenantAndGateway";

function req(body: any, method = "POST"): any {
  return {
    method,
    headers: {
      authorization: "Bearer admin-token",
      "content-type": "application/json",
      origin: "https://admin.example.com",
    },
    rawBody: Buffer.from(JSON.stringify(body)),
    on: () => undefined,
    destroy: () => undefined,
  };
}

function res(): any {
  const headers: Record<string, string> = {};
  return {
    statusCode: 200,
    body: undefined,
    headers,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(body: any) {
      this.body = body;
      return this;
    },
    set(key: string, value: string) {
      headers[key] = value;
      return this;
    },
    setHeader(key: string, value: string) {
      headers[key] = value;
      return this;
    },
    getHeader(key: string) {
      return headers[key];
    },
    end() {
      return this;
    },
  };
}

const validBody = {
  tenantName: "North Facility",
  gatewayLabel: "Boiler Room ROK-01",
  onDutyTechnicianId: "tech-7",
  criticalLimits: { temp: { max: 80 } },
};

beforeEach(() => {
  (db as any).store.clear();
  vi.mocked(auth.verifyIdToken).mockResolvedValue({ uid: "admin-1", admin: true } as any);
});

describe("provisionTenantAndGateway", () => {
  it("creates tenant and gateway, returns the one-time token and sticker URL", async () => {
    const response = res();
    await (provisionTenantAndGateway as any)(req(validBody), response);

    expect(response.statusCode).toBe(201);
    expect(response.body.rawToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(response.body.model).toBe("ROK-01");
    expect(response.body.qrStickerUrl).toContain(`/stickers/${response.body.tenantId}/${response.body.gatewayId}#t=`);
    expect(response.body.activationUrl).toContain("/activate#");
    expect(response.body.qrSvgDataUrl).toMatch(/^data:image\/svg\+xml;base64,/);

    const hash = createHash("sha256").update(response.body.rawToken).digest("hex");
    const store = (db as any).store as Map<string, any>;
    expect(store.has(`gatewayTokens/${hash}`)).toBe(true);
    expect(JSON.stringify([...store])).not.toContain(response.body.rawToken);

    const gateway = store.get(`tenants/${response.body.tenantId}/gateways/${response.body.gatewayId}`);
    expect(gateway).toMatchObject({
      model: "ROK-01",
      tokenHash: hash,
      status: "PROVISIONING",
      criticalLimits: { temp: { max: 80 } },
    });
    expect(store.get(`tenants/${response.body.tenantId}`)).toMatchObject({
      name: "North Facility",
      onDutyTechnicianId: "tech-7",
      status: "ACTIVE",
    });
  });

  it("rejects non-admin callers and invalid payloads", async () => {
    vi.mocked(auth.verifyIdToken).mockResolvedValue({ uid: "u", admin: false } as any);
    const forbidden = res();
    await (provisionTenantAndGateway as any)(req(validBody), forbidden);
    expect(forbidden.statusCode).toBe(403);

    vi.mocked(auth.verifyIdToken).mockResolvedValue({ uid: "admin-1", admin: true } as any);
    const invalid = res();
    await (provisionTenantAndGateway as any)(req({ tenantName: "" }), invalid);
    expect(invalid.statusCode).toBe(400);
  });

  it("rejects non-POST methods", async () => {
    const response = res();
    await (provisionTenantAndGateway as any)(req(validBody, "GET"), response);
    expect(response.statusCode).toBe(405);
  });
});
