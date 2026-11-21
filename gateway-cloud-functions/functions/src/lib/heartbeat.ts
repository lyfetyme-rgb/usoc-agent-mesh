import { config } from "../config";
import { Timestamp } from "./firestore";

/** Anything with lastSeenAt strictly older than this is considered silent. */
export function offlineCutoff(nowMs: number = Date.now()): Timestamp {
  return Timestamp.fromMillis(nowMs - config.offlineThresholdMs);
}

export function isStale(lastSeenAt: unknown, cutoffMillis: number): boolean {
  const candidate = lastSeenAt as { toMillis?: () => number } | undefined;
  if (!candidate || typeof candidate.toMillis !== "function") return false;
  return candidate.toMillis() < cutoffMillis;
}
