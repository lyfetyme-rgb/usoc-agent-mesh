import { applicationDefault, getApps, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { FieldValue, getFirestore, Timestamp } from "firebase-admin/firestore";

if (getApps().length === 0) {
  initializeApp({ credential: applicationDefault() });
}

export const db = getFirestore();
export const auth = getAuth();
export { FieldValue, Timestamp };

export function now(): Timestamp {
  return Timestamp.now();
}

export const paths = {
  tenants: "tenants",
  technicians: "technicians",
  alerts: "alerts",
  customerRequests: "customerRequests",
  gatewayTokens: "gatewayTokens",

  tenant: (tenantId: string) => `tenants/${tenantId}`,
  gateway: (tenantId: string, gatewayId: string) => `tenants/${tenantId}/gateways/${gatewayId}`,
  packets: (tenantId: string, gatewayId: string) => `tenants/${tenantId}/gateways/${gatewayId}/packets`,
  rollups: (tenantId: string, gatewayId: string) => `tenants/${tenantId}/gateways/${gatewayId}/rollups`,
} as const;
