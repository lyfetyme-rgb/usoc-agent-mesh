import { config } from "../config";
import type { AlertKind, BreachInfo } from "../types";

export function sanitizeIdPart(value: string): string {
  return value.replace(/[^A-Za-z0-9_-]/g, "_");
}

/** Deterministic IDs give one open alert per gateway/metric episode. */
export function breachAlertId(gatewayId: string, metric: string): string {
  return `breach_${sanitizeIdPart(gatewayId)}_${sanitizeIdPart(metric)}`;
}

export function connectivityAlertId(gatewayId: string): string {
  return `connectivity_${sanitizeIdPart(gatewayId)}`;
}

export function dedupeKey(kind: AlertKind, gatewayId?: string, metric?: string): string {
  return [kind, gatewayId ?? "", metric ?? ""].join(":");
}

/** HTTPS universal links work everywhere; a custom app scheme is used if configured. */
export function alertDeepLink(alertId: string): string {
  const id = encodeURIComponent(alertId);
  if (config.appDeepLinkScheme) return `${config.appDeepLinkScheme}://alerts/${id}`;
  return `${config.appBaseUrl}/alerts/${id}?source=sms`;
}

export function describeBreach(gatewayId: string, breach: BreachInfo): string {
  const bound = breach.direction === "above_max" ? "above max" : "below min";
  return `Gateway ${gatewayId}: ${breach.metric}=${breach.value} ${bound} ${breach.limit}`;
}

export function connectivityMessage(gatewayId: string, silentForMs: number): string {
  const minutes = Math.round(silentForMs / 60_000);
  return `Gateway ${gatewayId} is OFFLINE (silent for ${minutes}+ min). Check connectivity now.`;
}

export function customerRequestMessage(subject?: string): string {
  return `New Customer Request Form received${subject ? `: ${subject}` : "."}`;
}
