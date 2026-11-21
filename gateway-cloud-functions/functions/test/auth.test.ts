import { createHash } from "node:crypto";
import type { Request } from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { newRawToken, resolveGateway, safeHexEqual, sha256Hex, verifyAdmin } from "../src/lib/auth";
import { HttpError } from "../src/lib/validation";

vi.mock("../src/lib/firestore", async () => {
  const { FakeFirestore, fakePaths, fakeTimestamp } = await import("./helpers/fakeFirestore");
  return {
    db: new FakeFirestore(),
    auth: { verifyIdToken: vi.fn() },
    paths: fakePaths,
    now: () => fakeTimestamp(1_700_000_000_000),
    Timestamp: {
      now: () => fakeTimestamp(1_700_000_000_000),
      fromMillis: (ms: number) => fakeTimestamp(ms),
    },
    FieldValue: { delete: () => ({ __fakeDelete: true }) },
  };
});

import { auth, db } from "../src/lib/firestore";

const TOKEN = "raw-token-abc";
const TOKEN_HASH = createHash("sha256").update(TOKEN).digest("hex");
const TENANT = "tenant-1";
const GATEWAY = "gw-1";

beforeEach(() => {
  (db as any).store.clear();
  vi.mocked(auth.verifyIdToken).mockReset();
});

describe("token primitives", () => {
  it("hashes with SHA-256", () => {
    expect(sha256Hex("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("compares hex digests in constant time", () => {
    expect(safeHexEqual(TOKEN_HASH, TOKEN_HASH)).toBe(true);
    expect(safeHexEqual(TOKEN_HASH, "0".repeat(64))).toBe(false);
    expect(safeHexEqual("not-hex", "0".repeat(64))).toBe(false);
  });

  it("mints unique high-entropy tokens", () => {
    const a = newRawToken();
    const b = newRawToken();
    expect(a).not.toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});

describe("resolveGateway", () => {
  function seed(status = "ONLINE", gatewayHash = TOKEN_HASH) {
    (db as any).store.set(`gatewayTokens/${TOKEN_HASH}`, {
      tenantId: TENANT,
      gatewayId: GATEWAY,
      createdAt: fakeNow(),
      revokedAt: null,
    });
    (db as any).store.set(`tenants/${TENANT}/gateways/${GATEWAY}`, {
      model: "ROK-01",
      tokenHash: gatewayHash,
      status,
      criticalLimits: {},
      createdAt: fakeNow(),
    });
  }

  function fakeNow() {
    return { toMillis: () => 1_700_000_000_000 };
  }

  it("resolves a valid token binding", async () => {
    seed();
    const result = await resolveGateway(TOKEN, GATEWAY);
    expect(result).toMatchObject({ tenantId: TENANT, gatewayId: GATEWAY, tokenHash: TOKEN_HASH });
  });

  it("rejects wrong tokens, wrong gateways and revoked credentials", async () => {
    seed();
    expect(await resolveGateway("wrong", GATEWAY)).toBeNull();
    expect(await resolveGateway(TOKEN, "other-gateway")).toBeNull();
    seed("REVOKED");
    expect(await resolveGateway(TOKEN, GATEWAY)).toBeNull();
  });

  it("rejects a hash mismatch between token and gateway", async () => {
    seed("ONLINE", "0".repeat(64));
    expect(await resolveGateway(TOKEN, GATEWAY)).toBeNull();
  });
});

describe("verifyAdmin", () => {
  function adminRequest(): Request {
    return { headers: { authorization: "Bearer admin-token" } } as Request;
  }

  it("accepts an admin claim", async () => {
    vi.mocked(auth.verifyIdToken).mockResolvedValue({ uid: "u1", admin: true } as any);
    await expect(verifyAdmin(adminRequest())).resolves.toEqual({ uid: "u1" });
  });

  it("rejects missing tokens, non-admin claims and invalid tokens", async () => {
    await expect(verifyAdmin({ headers: {} } as Request)).rejects.toMatchObject({
      status: 401,
    });
    vi.mocked(auth.verifyIdToken).mockResolvedValue({ uid: "u1", admin: false } as any);
    await expect(verifyAdmin(adminRequest())).rejects.toMatchObject({ status: 403 });
    vi.mocked(auth.verifyIdToken).mockRejectedValue(new Error("expired"));
    await expect(verifyAdmin(adminRequest())).rejects.toBeInstanceOf(HttpError);
  });
});
