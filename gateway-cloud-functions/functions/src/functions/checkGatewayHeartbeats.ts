import { onSchedule } from "firebase-functions/v2/scheduler";
import { config } from "../config";
import { connectivityAlertId, connectivityMessage, dedupeKey } from "../lib/alerts";
import { db, now, paths } from "../lib/firestore";
import { isStale, offlineCutoff } from "../lib/heartbeat";
import type { AlertDoc, GatewayDoc } from "../types";

/**
 * Cloud Scheduler runs this every minute, independent of any browser. Gateways
 * silent for more than 180 seconds are flipped to OFFLINE and raise one
 * critical connectivity alert per episode.
 */
export const checkGatewayHeartbeats = onSchedule(
  { schedule: config.heartbeatSchedule, timeZone: "UTC" },
  async () => {
    const detectedAt = now();
    const cutoff = offlineCutoff(detectedAt.toMillis());

    // Single-field query: works without a composite index. Status is filtered
    // in code so REVOKED/OFFLINE devices never generate duplicate alerts.
    const snapshot = await db
      .collectionGroup("gateways")
      .where("lastSeenAt", "<", cutoff)
      .get();

    const batch = db.batch();
    let flipped = 0;

    for (const doc of snapshot.docs) {
      const gateway = doc.data() as GatewayDoc;
      if (gateway.status === "OFFLINE" || gateway.status === "REVOKED") continue;
      if (!isStale(gateway.lastSeenAt, cutoff.toMillis())) continue;

      const tenantId = doc.ref.parent.parent?.id;
      if (!tenantId) continue;
      const gatewayId = doc.id;

      batch.update(doc.ref, {
        status: "OFFLINE",
        offlineSince: detectedAt,
        updatedAt: detectedAt,
      });

      const alert: AlertDoc = {
        kind: "CONNECTIVITY",
        tenantId,
        gatewayId,
        message: connectivityMessage(gatewayId, config.offlineThresholdMs),
        dedupeKey: dedupeKey("CONNECTIVITY", gatewayId),
        status: "OPEN",
        createdAt: detectedAt,
        updatedAt: detectedAt,
      };
      batch.set(db.doc(`${paths.alerts}/${connectivityAlertId(gatewayId)}`), alert);
      flipped += 1;
    }

    if (flipped > 0) await batch.commit();
    console.log(`Heartbeat check complete: ${flipped} gateway(s) flipped OFFLINE`);
  },
);
