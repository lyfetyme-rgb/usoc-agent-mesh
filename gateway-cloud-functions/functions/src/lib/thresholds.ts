import type { BreachInfo, GatewayDoc, NumericPayload } from "../types";

/** Server-side Critical Limit evaluation. The device never decides what is critical. */
export function detectBreaches(
  readings: NumericPayload,
  gateway: Pick<GatewayDoc, "criticalLimits" | "globalCriticalLimit">,
): BreachInfo[] {
  const breaches: BreachInfo[] = [];
  for (const [metric, value] of Object.entries(readings)) {
    const limit = gateway.criticalLimits?.[metric];

    if (limit) {
      if (typeof limit.max === "number" && value > limit.max) {
        breaches.push({ metric, value, limit: limit.max, direction: "above_max" });
      } else if (typeof limit.min === "number" && value < limit.min) {
        breaches.push({ metric, value, limit: limit.min, direction: "below_min" });
      }
      continue;
    }

    if (typeof gateway.globalCriticalLimit === "number" && value > gateway.globalCriticalLimit) {
      breaches.push({
        metric,
        value,
        limit: gateway.globalCriticalLimit,
        direction: "above_max",
      });
    }
  }
  return breaches;
}
