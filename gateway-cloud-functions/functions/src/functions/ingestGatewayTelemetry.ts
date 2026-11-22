import { randomUUID } from "node:crypto";
import { onRequest } from "firebase-functions/v2/https";
import { config, TTL_MS } from "../config";
import { resolveGateway, safeHexEqual } from "../lib/auth";
import { breachAlertId, connectivityAlertId, dedupeKey, describeBreach } from "../lib/alerts";
import { db, FieldValue, now, paths, Timestamp } from "../lib/firestore";
import { asRollupDoc, hourKey, mergeRollup } from "../lib/rollups";
import { logDuration, logError } from "../lib/observability";
import { detectBreaches } from "../lib/thresholds";
import {
  HttpError,
  bearerToken,
  header,
  parseNumericPayload,
  readRawBody,
  respondWithError,
} from "../lib/validation";
import type { AlertDoc, GatewayDoc, GatewayTokenDoc, PacketDoc, RollupDoc } from "../types";

/**
 * One-way HTTPS ingress. The response carries no telemetry or commands, the
 * body is strictly numeric and <4 KB, and every side effect is committed in a
 * single Firestore transaction.
 */
export const ingestGatewayTelemetry = onRequest(async (req, res) => {
  if (req.method !== "POST") {
    res.set("Allow", "POST").status(405).json({ error: "METHOD_NOT_ALLOWED" });
    return;
  }

  const requestId = header(req, "x-request-id") ?? randomUUID();
  const started = Date.now();

  try {
    const raw = await readRawBody(req, config.maxBodyBytes);
    const readings = parseNumericPayload(raw, config.maxBodyBytes);

    const gatewayId = header(req, "x-gateway-id");
    const token = header(req, "x-gateway-token") ?? bearerToken(req);
    if (!gatewayId || !token) {
      throw new HttpError(401, "UNAUTHENTICATED", "X-Gateway-ID and gateway token are required");
    }

    const resolved = await resolveGateway(token, gatewayId);
    if (!resolved) throw new HttpError(401, "UNAUTHENTICATED", "Invalid gateway credentials");

    const tenantId = resolved.tenantId;
    const tokenRef = db.collection(paths.gatewayTokens).doc(resolved.tokenHash);
    const gatewayRef = db.doc(paths.gateway(tenantId, gatewayId));
    const packetRef = db.collection(paths.packets(tenantId, gatewayId)).doc();

    const receivedAt = now();
    const rollupRef = db.doc(
      `${paths.rollups(tenantId, gatewayId)}/${hourKey(receivedAt)}`,
    );

    const limitMetrics = new Set(Object.keys(resolved.gateway.criticalLimits ?? {}));
    if (typeof resolved.gateway.globalCriticalLimit === "number") {
      for (const metric of Object.keys(readings)) limitMetrics.add(metric);
    }
    // Two different metric names can sanitize to the same alert document ID.
    // Deduplicate by final ID so one packet never writes a document twice in a
    // single Firestore transaction.
    const breachTargets = new Map<string, { metric: string; ref: ReturnType<typeof db.doc> }>();
    for (const metric of limitMetrics) {
      const id = breachAlertId(gatewayId, metric);
      if (!breachTargets.has(id)) breachTargets.set(id, { metric, ref: db.doc(`${paths.alerts}/${id}`) });
    }
    const targets = [...breachTargets.values()];
    const metricList = targets.map((target) => target.metric);
    const breachRefs = targets.map((target) => target.ref);
    const connectivityRef = db.doc(`${paths.alerts}/${connectivityAlertId(gatewayId)}`);

    const transactionStarted = Date.now();
    await db.runTransaction(async (tx) => {
      // All reads first — Firestore requires this before any write in a tx.
      const [tokenSnap, gatewaySnap, rollupSnap, ...alertSnaps] = await Promise.all([
        tx.get(tokenRef),
        tx.get(gatewayRef),
        tx.get(rollupRef),
        ...breachRefs.map((ref) => tx.get(ref)),
        tx.get(connectivityRef),
      ]);
      const connectivitySnap = alertSnaps[alertSnaps.length - 1];
      const breachSnaps = alertSnaps.slice(0, metricList.length);

      const storedToken = tokenSnap.exists ? (tokenSnap.data() as GatewayTokenDoc) : undefined;
      if (!storedToken || storedToken.revokedAt) {
        throw new HttpError(401, "UNAUTHENTICATED", "Gateway token has been revoked");
      }

      const gateway = gatewaySnap.exists ? (gatewaySnap.data() as GatewayDoc) : undefined;
      if (
        !gateway ||
        gateway.status === "REVOKED" ||
        !safeHexEqual(gateway.tokenHash, resolved.tokenHash)
      ) {
        throw new HttpError(401, "UNAUTHENTICATED", "Gateway is not active");
      }

      const breaches = detectBreaches(readings, gateway);
      const breachByMetric = new Map(breaches.map((breach) => [breach.metric, breach]));

      const packet: PacketDoc = {
        tenantId,
        gatewayId,
        readings: { ...readings },
        receivedAt,
        expireAt: Timestamp.fromMillis(receivedAt.toMillis() + TTL_MS),
        breachCount: breaches.length,
        breaches,
        requestId,
      };
      tx.set(packetRef, packet);

      const previous = rollupSnap.exists ? (rollupSnap.data() as RollupDoc) : undefined;
      tx.set(
        rollupRef,
        asRollupDoc(
          mergeRollup(previous, Object.values(readings), breaches.length),
          tenantId,
          gatewayId,
          receivedAt,
        ),
      );

      const gatewayUpdate: Record<string, unknown> = {
        status: "ONLINE",
        lastSeenAt: receivedAt,
        updatedAt: receivedAt,
      };
      if (gateway.offlineSince) gatewayUpdate.offlineSince = FieldValue.delete();
      tx.update(gatewayRef, gatewayUpdate);

      const tokenUpdate: Record<string, unknown> = { lastUsedAt: receivedAt };
      if (!storedToken.activatedAt) tokenUpdate.activatedAt = receivedAt;
      tx.update(tokenRef, tokenUpdate);

      breachRefs.forEach((ref, index) => {
        const metric = metricList[index];
        const breach = breachByMetric.get(metric);
        const existing = breachSnaps[index];
        if (breach) {
          const previousAlert = existing?.exists ? (existing.data() as AlertDoc) : undefined;
          const alert: AlertDoc = {
            kind: "CRITICAL_LIMIT",
            tenantId,
            gatewayId,
            metric: breach.metric,
            value: breach.value,
            limit: breach.limit,
            direction: breach.direction,
            message: describeBreach(gatewayId, breach),
            dedupeKey: dedupeKey("CRITICAL_LIMIT", gatewayId, breach.metric),
            status: "OPEN",
            createdAt: previousAlert?.createdAt ?? receivedAt,
            updatedAt: receivedAt,
            requestId,
          };
          tx.set(ref, alert);
        } else if (existing?.exists && (existing.data() as AlertDoc).status === "OPEN") {
          tx.delete(ref);
        }
      });

      // A successful packet clears the offline episode and its alert.
      if (connectivitySnap?.exists && gateway.status === "OFFLINE") {
        tx.delete(connectivityRef);
      }
    });

    logDuration("ingest.transaction", Date.now() - transactionStarted, { request_id: requestId, gateway_id: gatewayId });
    // Data diode: acknowledge only, never return stored data or commands.
    // The trace id echoes back so a gateway can log the exact accepted packet.
    res.set("X-Request-ID", requestId).status(204).end();
  } catch (error) {
    logError({
      source: "ingestGatewayTelemetry",
      error,
      requestId,
      code: error instanceof HttpError ? error.code : undefined,
    });
    logDuration("ingest.total", Date.now() - started, { request_id: requestId, outcome: "error" });
    respondWithError(res, error);
  }
});
