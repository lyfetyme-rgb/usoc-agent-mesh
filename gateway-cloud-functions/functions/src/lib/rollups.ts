import type { RollupDoc } from "../types";

export interface RollupValues {
  min: number;
  max: number;
  breachCount: number;
  sampleCount: number;
}

type TimeLike = number | Date | { toMillis(): number };

/** UTC bucket key, e.g. "2026-11-20T14" for the 14:00 hour. */
export function hourKey(at: TimeLike): string {
  const millis = typeof at === "number" ? at : at instanceof Date ? at.getTime() : at.toMillis();
  return new Date(millis).toISOString().slice(0, 13);
}

/** Pure min/max/count fold used inside the Firestore transaction. */
export function mergeRollup(
  previous: RollupValues | undefined,
  values: number[],
  breachCount: number,
): RollupValues {
  if (values.length === 0) throw new Error("Cannot merge an empty packet");
  const packetMin = Math.min(...values);
  const packetMax = Math.max(...values);
  return {
    min: previous ? Math.min(previous.min, packetMin) : packetMin,
    max: previous ? Math.max(previous.max, packetMax) : packetMax,
    breachCount: (previous?.breachCount ?? 0) + breachCount,
    sampleCount: (previous?.sampleCount ?? 0) + 1,
  };
}

export function asRollupDoc(
  values: RollupValues,
  tenantId: string,
  gatewayId: string,
  updatedAt: RollupDoc["updatedAt"],
): RollupDoc {
  return {
    hour: hourKey(updatedAt),
    tenantId,
    gatewayId,
    ...values,
    updatedAt,
  };
}
