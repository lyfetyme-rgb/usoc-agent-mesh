import type { DocumentReference } from "firebase-admin/firestore";
import { onDocumentCreated } from "firebase-functions/v2/firestore";
import { db, FieldValue, now } from "../lib/firestore";
import { customerRequestMessage } from "../lib/alerts";
import { sendAlertSms } from "../lib/notification";
import { logError } from "../lib/observability";
import type { AlertDoc } from "../types";

type CustomerRequestDoc = {
  tenantId: string;
  subject?: string;
  notifiedAt?: unknown;
};

/**
 * Claim the notification before handing it to Twilio. A trigger redelivery or
 * a retry after a successful send then sees notifiedAt and sends nothing.
 * If the send fails, release the claim so the trigger can retry safely.
 */
async function claimNotification(ref: DocumentReference, requireOpen = true): Promise<boolean> {
  return db.runTransaction(async (tx) => {
    const fresh = await tx.get(ref);
    const data = fresh.exists ? (fresh.data() as { status?: string; notifiedAt?: unknown }) : null;
    if (!data || data.notifiedAt || (requireOpen && data.status !== "OPEN")) return false;
    tx.update(ref, { notifiedAt: now() });
    return true;
  });
}

async function releaseClaim(ref: DocumentReference): Promise<void> {
  await ref.update({ notifiedAt: FieldValue.delete() });
}

/** Any OPEN alert document (breach or offline) results in one SMS to on-duty. */
export const dispatchAlertNotification = onDocumentCreated(
  "alerts/{alertId}",
  async (event) => {
    const snapshot = event.data;
    if (!snapshot) return;
    const alert = snapshot.data() as AlertDoc;
    if (alert.status !== "OPEN" || alert.notifiedAt) return;
    if (!(await claimNotification(snapshot.ref))) return;

    try {
      const sent = await sendAlertSms({
        tenantId: alert.tenantId,
        alertId: event.params.alertId,
        kind: alert.kind,
        message: alert.message,
      });
      if (!sent) await releaseClaim(snapshot.ref);
    } catch (error) {
      logError({ source: "dispatchAlertNotification", error, requestId: alert.requestId });
      await releaseClaim(snapshot.ref);
      throw error;
    }
  },
);

/** Customer Request Forms are a separate ingress but share the SMS dispatcher. */
export const dispatchCustomerRequestNotification = onDocumentCreated(
  "customerRequests/{requestId}",
  async (event) => {
    const snapshot = event.data;
    if (!snapshot) return;
    const request = snapshot.data() as CustomerRequestDoc;
    if (request.notifiedAt || !request.tenantId) return;
    if (!(await claimNotification(snapshot.ref, false))) return;

    try {
      const sent = await sendAlertSms({
        tenantId: request.tenantId,
        alertId: event.params.requestId,
        kind: "CUSTOMER_REQUEST",
        message: customerRequestMessage(request.subject),
      });
      if (!sent) await releaseClaim(snapshot.ref);
    } catch (error) {
      logError({ source: "dispatchCustomerRequestNotification", error, requestId: event.params.requestId });
      await releaseClaim(snapshot.ref);
      throw error;
    }
  },
);
