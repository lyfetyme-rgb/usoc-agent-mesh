import { onDocumentCreated } from "firebase-functions/v2/firestore";
import { now } from "../lib/firestore";
import { customerRequestMessage } from "../lib/alerts";
import { sendAlertSms } from "../lib/notification";
import type { AlertDoc } from "../types";

type CustomerRequestDoc = {
  tenantId: string;
  subject?: string;
  notifiedAt?: unknown;
};

/** Any OPEN alert document (breach or offline) results in one SMS to on-duty. */
export const dispatchAlertNotification = onDocumentCreated(
  "alerts/{alertId}",
  async (event) => {
    const snapshot = event.data;
    if (!snapshot) return;
    const alert = snapshot.data() as AlertDoc;
    if (alert.notifiedAt) return;

    const sent = await sendAlertSms({
      tenantId: alert.tenantId,
      alertId: event.params.alertId,
      kind: alert.kind,
      message: alert.message,
    });
    if (sent) await snapshot.ref.update({ notifiedAt: now() });
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

    const sent = await sendAlertSms({
      tenantId: request.tenantId,
      alertId: event.params.requestId,
      kind: "CUSTOMER_REQUEST",
      message: customerRequestMessage(request.subject),
    });
    if (sent) await snapshot.ref.update({ notifiedAt: now() });
  },
);
