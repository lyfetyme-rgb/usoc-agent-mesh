// Atlas shared contracts

export interface TenantContext {
  tenantId: string;
  facilityId?: string;
  buildingId?: string;
  assetId?: string;
  deviceId?: string;
  modelId?: string;
  userId?: string;
}

export interface ShadAuditEvent {
  eventId: string;
  tenantId: string;
  facilityId?: string;
  assetId?: string;
  timestamp: string;
  modelId?: string;
  modelVersion?: string;
  automationTask: string;
  eventType:
    | "HALLUCINATION_PROBE"
    | "HALLUCINATION_BLOCK"
    | "DATA_POISONING"
    | "BIAS_THRESHOLD"
    | "POLICY_EVALUATION"
    | "GUARDRAIL_ACTIVATED"
    | "COMMAND_BLOCKED"
    | "MODEL_DRIFT"
    | "ANOMALY";
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  riskScore: number;
  confidenceScore?: number;
  inputHash?: string;
  outputHash?: string;
  resolvedAction: string;
  previousEventHash: string;
  eventHash: string;
  actor: { type: "USER" | "MODEL" | "SYSTEM" | "EDGE"; id: string };
}

export interface RiskVector {
  aiRisk: number;
  cyberRisk: number;
  dataRisk: number;
  assetRisk: number;
  policyRisk: number;
  operationalRisk: number;
  modelRisk: number;
}

export function calculateRisk(v: RiskVector): number {
  const raw =
    v.aiRisk * 0.2 +
    v.cyberRisk * 0.2 +
    v.dataRisk * 0.15 +
    v.assetRisk * 0.2 +
    v.policyRisk * 0.1 +
    v.operationalRisk * 0.1 +
    v.modelRisk * 0.05;
  return Math.min(1, Math.max(0, raw));
}

export type RiskDecision = "ALLOW" | "HOLD" | "DENY" | "CONTAIN";

export interface TrustFunnelStage {
  name: string;
  passed: boolean;
  detail?: string;
  score?: number;
}

export interface TrustFunnelResult {
  decision: RiskDecision;
  blocked: boolean;
  reasons: string[];
  stages: TrustFunnelStage[];
  riskScore: number;
  requiresHumanReview: boolean;
}

// Hash chain utilities
import { createHash } from "node:crypto";

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

export function computeEventHash(event: Omit<ShadAuditEvent, "eventHash">): string {
  const canonical = JSON.stringify(event);
  return sha256Hex(canonical + event.previousEventHash);
}

export function verifyChain(events: ShadAuditEvent[]): { ok: boolean; brokenAt?: number } {
  let prev = "GENESIS";
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    if (e.previousEventHash !== prev) return { ok: false, brokenAt: i };
    const { eventHash: _h, ...rest } = e;
    const r = computeEventHash({ ...rest } as any);
    if (r !== e.eventHash) return { ok: false, brokenAt: i };
    prev = e.eventHash;
  }
  return { ok: true };
}

export const GENESIS_HASH = "GENESIS";

export interface ModelIdentity {
  modelId: string;
  modelVersion: string;
}

export interface ProposedCommand {
  tenantId: string;
  facilityId?: string;
  assetId?: string;
  modelId?: string;
  modelVersion?: string;
  action: string;
  target?: string;
  confidence?: number;
  dataIntegrityOk?: boolean;
  modelIntegrityOk?: boolean;
  poisoningDetected?: boolean;
  biasDetected?: boolean;
  driftDetected?: boolean;
  assetHealthOk?: boolean;
  physicalEnvelopeOk?: boolean;
  cyberRisk?: number;
  actor: { type: "USER" | "MODEL" | "SYSTEM" | "EDGE"; id: string };
}