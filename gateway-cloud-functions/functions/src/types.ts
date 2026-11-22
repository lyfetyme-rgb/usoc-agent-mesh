import type { Timestamp } from "firebase-admin/firestore";

export type NumericPayload = Record<string, number>;

export type GatewayStatus = "PROVISIONING" | "ONLINE" | "OFFLINE" | "REVOKED";

export type CriticalLimit = {
  /** Inclusive lower bound; a value below this is a breach. */
  min?: number;
  /** Inclusive upper bound; a value above this is a breach. */
  max?: number;
};

export type GatewayDoc = {
  model: "ROK-01";
  label?: string;
  tokenHash: string;
  status: GatewayStatus;
  criticalLimits: Record<string, CriticalLimit>;
  /** Optional catch-all upper limit applied to every reading. */
  globalCriticalLimit?: number;
  /** Absent until the first packet arrives (so the watchdog ignores new boxes). */
  lastSeenAt?: Timestamp;
  offlineSince?: Timestamp;
  createdAt: Timestamp;
  updatedAt?: Timestamp;
};

export type GatewayTokenDoc = {
  tenantId: string;
  gatewayId: string;
  createdAt: Timestamp;
  activatedAt?: Timestamp;
  lastUsedAt?: Timestamp;
  revokedAt?: Timestamp;
};

export type AlertKind = "CRITICAL_LIMIT" | "CONNECTIVITY" | "CUSTOMER_REQUEST";

export type AlertDoc = {
  kind: AlertKind;
  tenantId: string;
  gatewayId?: string;
  metric?: string;
  value?: number;
  limit?: number;
  direction?: "above_max" | "below_min";
  message: string;
  dedupeKey: string;
  status: "OPEN" | "RESOLVED";
  createdAt: Timestamp;
  updatedAt: Timestamp;
  notifiedAt?: Timestamp;
  deepLink?: string;
  subject?: string;
  /** Correlates the alert with the ingress request that raised it. */
  requestId?: string;
};

export type RollupDoc = {
  hour: string;
  tenantId: string;
  gatewayId: string;
  min: number;
  max: number;
  breachCount: number;
  sampleCount: number;
  updatedAt: Timestamp;
};

export type BreachInfo = {
  metric: string;
  value: number;
  limit: number;
  direction: "above_max" | "below_min";
};

export type PacketDoc = {
  tenantId: string;
  gatewayId: string;
  readings: NumericPayload;
  receivedAt: Timestamp;
  expireAt: Timestamp;
  breachCount: number;
  breaches: BreachInfo[];
  /** Accepted client trace id, or a generated one when the gateway omitted it. */
  requestId?: string;
};
