import { describe, expect, it } from "vitest";
import { asRollupDoc, hourKey, mergeRollup } from "../src/lib/rollups";

describe("hourKey", () => {
  it("buckets by UTC hour", () => {
    expect(hourKey(Date.UTC(2026, 10, 20, 14, 37, 12))).toBe("2026-11-20T14");
    expect(hourKey({ toMillis: () => Date.UTC(2026, 0, 1, 0, 5) })).toBe("2026-01-01T00");
  });
});

describe("mergeRollup", () => {
  it("starts from the first packet", () => {
    expect(mergeRollup(undefined, [10, 4, 7], 0)).toEqual({
      min: 4,
      max: 10,
      breachCount: 0,
      sampleCount: 1,
    });
  });

  it("folds min, max, breachCount and sampleCount", () => {
    const first = mergeRollup(undefined, [10, 4], 1);
    const second = mergeRollup(first, [12, 3], 2);
    expect(second).toEqual({ min: 3, max: 12, breachCount: 3, sampleCount: 2 });
  });

  it("refuses to merge empty packets", () => {
    expect(() => mergeRollup(undefined, [], 0)).toThrow(/empty/);
  });
});

describe("asRollupDoc", () => {
  it("adds identity and timestamp fields", () => {
    const stamp = { toMillis: () => 0 };
    const doc = asRollupDoc(
      { min: 1, max: 2, breachCount: 0, sampleCount: 1 },
      "tenant",
      "gw",
      stamp as any,
    );
    expect(doc).toMatchObject({ tenantId: "tenant", gatewayId: "gw", min: 1, max: 2 });
    expect(doc.updatedAt).toBe(stamp);
  });
});
