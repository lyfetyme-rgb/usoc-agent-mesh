import { onRequest } from "firebase-functions/v2/https";
import { z } from "zod";
import { newRawToken, sha256Hex, verifyAdmin } from "../lib/auth";
import { db, now, paths } from "../lib/firestore";
import { buildActivationUrl, buildQrSvgDataUrl, buildQrStickerUrl } from "../lib/qr";
import { HttpError, applyCors, readRawBody, respondWithError } from "../lib/validation";
import type { GatewayDoc } from "../types";

const criticalLimitSchema = z
  .object({
    min: z.number().finite().optional(),
    max: z.number().finite().optional(),
  })
  .refine((value) => value.min === undefined || value.max === undefined || value.min <= value.max, {
    message: "min must be less than or equal to max",
  });

const requestSchema = z
  .object({
    tenantName: z.string().min(1).max(120),
    gatewayLabel: z.string().min(1).max(80).optional(),
    onDutyTechnicianId: z.string().min(1).max(128).optional(),
    criticalLimits: z.record(criticalLimitSchema).optional(),
    globalCriticalLimit: z.number().finite().optional(),
  })
  .strict();

/** Creates a tenant + ROK-01 gateway, discloses the raw token once, returns the sticker URL. */
export const provisionTenantAndGateway = onRequest(async (req, res) => {
  if (applyCors(req, res)) return;

  if (req.method !== "POST") {
    res.set("Allow", "POST").status(405).json({ error: "METHOD_NOT_ALLOWED" });
    return;
  }

  try {
    await verifyAdmin(req);

    const raw = await readRawBody(req, 16 * 1024);
    let json: unknown;
    try {
      json = JSON.parse(raw.toString("utf8"));
    } catch {
      throw new HttpError(400, "INVALID_PAYLOAD", "Body must be valid JSON");
    }
    const input = requestSchema.parse(json);

    const createdAt = now();
    const tenantRef = db.collection(paths.tenants).doc();
    const gatewayRef = tenantRef.collection("gateways").doc();
    const rawToken = newRawToken();
    const tokenHash = sha256Hex(rawToken);

    const gatewayDoc: GatewayDoc = {
      model: "ROK-01",
      label: input.gatewayLabel ?? `ROK-01 (${input.tenantName})`,
      tokenHash,
      status: "PROVISIONING",
      criticalLimits: input.criticalLimits ?? {},
      createdAt,
    };
    if (input.globalCriticalLimit !== undefined) {
      gatewayDoc.globalCriticalLimit = input.globalCriticalLimit;
    }

    const batch = db.batch();
    batch.set(tenantRef, {
      name: input.tenantName,
      status: "ACTIVE",
      onDutyTechnicianId: input.onDutyTechnicianId ?? null,
      createdAt,
      updatedAt: createdAt,
    });
    batch.set(gatewayRef, gatewayDoc);
    // The hash is the document ID: uniqueness and O(1) lookup at ingest time.
    batch.set(db.collection(paths.gatewayTokens).doc(tokenHash), {
      tenantId: tenantRef.id,
      gatewayId: gatewayRef.id,
      createdAt,
      revokedAt: null,
    });
    await batch.commit();

    const activationUrl = buildActivationUrl(tenantRef.id, gatewayRef.id, rawToken);
    const qrStickerUrl = buildQrStickerUrl(tenantRef.id, gatewayRef.id, rawToken);

    let qrSvgDataUrl = "";
    try {
      qrSvgDataUrl = await buildQrSvgDataUrl(activationUrl);
    } catch (error) {
      console.error("QR generation failed", error);
    }

    res.status(201).json({
      tenantId: tenantRef.id,
      gatewayId: gatewayRef.id,
      model: "ROK-01",
      rawToken,
      activationUrl,
      qrStickerUrl,
      qrSvgDataUrl,
      notice: "rawToken is returned once. Only its SHA-256 hash is stored.",
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      res.status(400).json({ error: "INVALID_PAYLOAD", message: error.message });
      return;
    }
    console.error("provisionTenantAndGateway failed", error);
    respondWithError(res, error);
  }
});
