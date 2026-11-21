import { config } from "../config";
import type { AlertKind } from "../types";
import { alertDeepLink } from "./alerts";
import { db, paths } from "./firestore";
import { sendSms } from "./twilio";

interface TechnicianDoc {
  phone?: string;
  name?: string;
}

interface TenantDoc {
  onDutyTechnicianId?: string;
}

export async function resolveOnDutyPhone(
  tenantId: string,
): Promise<{ phone?: string; technicianId?: string }> {
  const tenantSnap = await db.doc(paths.tenant(tenantId)).get();
  if (!tenantSnap.exists) return {};
  const tenant = tenantSnap.data() as TenantDoc;
  if (!tenant.onDutyTechnicianId) return {};

  const technicianSnap = await db.collection(paths.technicians).doc(tenant.onDutyTechnicianId).get();
  if (!technicianSnap.exists) return {};
  const technician = technicianSnap.data() as TechnicianDoc;
  return { phone: technician.phone, technicianId: tenant.onDutyTechnicianId };
}

/** Returns true when a message was actually handed to Twilio. */
export async function sendAlertSms(input: {
  tenantId: string;
  alertId: string;
  kind: AlertKind;
  message: string;
}): Promise<boolean> {
  const { phone } = await resolveOnDutyPhone(input.tenantId);
  const to = phone ?? config.alertFallbackPhone;
  if (!to) {
    console.warn(`No on-duty phone for tenant ${input.tenantId}; skipping SMS`);
    return false;
  }

  const tag = input.kind === "CUSTOMER_REQUEST" ? "[REQUEST]" : "[CRITICAL]";
  const body = `${tag} ${input.message}\nOpen: ${alertDeepLink(input.alertId)}`;
  await sendSms(to, body);
  return true;
}
