import { describe, expect, it, vi } from "vitest";
import { isStale, offlineCutoff } from "../src/lib/heartbeat";

vi.mock("../src/lib/firestore", async () => {
  const { fakeTimestamp } = await import("./helpers/fakeFirestore");
  return {
    Timestamp: { fromMillis: (ms: number) => fakeTimestamp(ms) },
  };
});

describe("offlineCutoff", () => {
  it("is exactly 180 seconds before now by default", () => {
    expect(offlineCutoff(1_700_000_000_000).toMillis()).toBe(1_699_999_820_000);
  });
});

describe("isStale", () => {
  const cutoff = 1_699_999_820_000;

  it("treats Firestore timestamps older than the cutoff as stale", () => {
    expect(isStale({ toMillis: () => cutoff - 1 }, cutoff)).toBe(true);
    expect(isStale({ toMillis: () => cutoff }, cutoff)).toBe(false);
  });

  it("ignores missing or malformed lastSeenAt values", () => {
    expect(isStale(undefined, cutoff)).toBe(false);
    expect(isStale(null, cutoff)).toBe(false);
    expect(isStale(123, cutoff)).toBe(false);
  });
});
