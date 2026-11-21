import { describe, expect, it } from "vitest";
import { detectBreaches } from "../src/lib/thresholds";

describe("detectBreaches", () => {
  const gateway = {
    criticalLimits: { temp: { min: 10, max: 80 }, pressure: { max: 100 } },
    globalCriticalLimit: 500,
  };

  it("flags values above a per-metric maximum", () => {
    expect(detectBreaches({ temp: 85 }, gateway)).toEqual([
      { metric: "temp", value: 85, limit: 80, direction: "above_max" },
    ]);
  });

  it("flags values below a per-metric minimum", () => {
    expect(detectBreaches({ temp: 5 }, gateway)).toEqual([
      { metric: "temp", value: 5, limit: 10, direction: "below_min" },
    ]);
  });

  it("applies the global critical limit to metrics without explicit limits", () => {
    expect(detectBreaches({ vibration: 600, pressure: 90 }, gateway)).toEqual([
      { metric: "vibration", value: 600, limit: 500, direction: "above_max" },
    ]);
  });

  it("returns no breaches for in-range readings", () => {
    expect(detectBreaches({ temp: 40, pressure: 95, vibration: 100 }, gateway)).toEqual([]);
  });

  it("ignores unconfigured metrics when no global limit exists", () => {
    expect(detectBreaches({ unknown: 1e9 }, { criticalLimits: {}, globalCriticalLimit: undefined })).toEqual([]);
  });
});
