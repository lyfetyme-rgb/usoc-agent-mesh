import { onSchedule } from "firebase-functions/v2/scheduler";
import { config } from "../config";
import { connectivityAlertId, connectivityMessage, dedupeKey } from "../lib/alerts";
import { db, now, paths } from "../lib/firestore";
import { isStale, offlineCutoff } from "../lib/heartbeat";
import type { AlertDoc, GatewayDoc } from "../types";

const FIRESTORE_BATCH_LIMIT = 500;
const WRITES_PER_GATEWAY = 2;

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

    // Filter on status in the query as well as in code: already-OFFLINE and
    // REVOKED gateways keep their old lastSeenAt, so a lastSeenAt-only query
    // would re-read the entire cumulative outage set on every run.
    const snapshot = await db
      .collectionGroup("gateways")
      .where("status", "==", "ONLINE")
      .where("lastSeenAt", "<", cutoff)
      .get();

    // Each gateway needs two writes (status + alert). Firestore caps a batch at
    // 500 operations, so flush at 250 gateways and never lose the tail of a
    // large outage to a failed commit.
    const maxGatewaysPerBatch = Math.floor(FIRESTORE_BATCH_LIMIT / WRITES_PER_GATEWAY);
    let batch = db.batch();
    let pending = 0;
    let flipped = 0;

    const commitBatch = async (): Promise<void> => {
      if (pending > 0) await batch.commit();
      batch = db.batch();
      pending = 0;
    };

    for (const doc of snapshot.docs) {
      const gateway = doc.data() as GatewayDoc;
      if (gateway.status !== "ONLINE") continue;
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
      pending += WRITES_PER_GATEWAY;
      flipped += 1;

      if (pending >= maxGatewaysPerBatch * WRITES_PER_GATEWAY) await commitBatch();
    }

    await commitBatch();
    console.log(`Heartbeat check complete: ${flipped} gateway(s) flipped OFFLINE`);
  },
);
