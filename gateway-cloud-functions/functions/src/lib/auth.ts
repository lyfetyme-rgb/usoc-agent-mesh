import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { Request } from "express";
import type { GatewayDoc, GatewayTokenDoc } from "../types";
import { auth, db, paths } from "./firestore";
import { HttpError, bearerToken } from "./validation";

const SHA256_HEX = /^[0-9a-f]{64}$/;

/** Hex SHA-256 of a raw token. The raw value is never persisted. */
export function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/** Constant-time comparison of two 64-char lowercase hex digests. */
export function safeHexEqual(left: string, right: string): boolean {
  if (!SHA256_HEX.test(left) || !SHA256_HEX.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

/** 256 bits of entropy, URL-safe. Displayed once at provisioning time. */
export function newRawToken(): string {
  return randomBytes(32).toString("base64url");
}

export interface ResolvedGateway {
  tenantId: string;
  gatewayId: string;
  tokenHash: string;
  gateway: GatewayDoc;
}

/**
 * Looks up a gateway by the SHA-256 digest of the presented token. Using the
 * digest as the document ID makes the lookup O(1) and guarantees that only the
 * hash is ever stored.
 */
export async function resolveGateway(
  rawToken: string,
  expectedGatewayId?: string,
): Promise<ResolvedGateway | null> {
  const tokenHash = sha256Hex(rawToken);
  const tokenSnap = await db.collection(paths.gatewayTokens).doc(tokenHash).get();
  if (!tokenSnap.exists) return null;

  const token = tokenSnap.data() as GatewayTokenDoc;
  if (token.revokedAt) return null;
  if (expectedGatewayId && token.gatewayId !== expectedGatewayId) return null;

  const gatewaySnap = await db.doc(paths.gateway(token.tenantId, token.gatewayId)).get();
  if (!gatewaySnap.exists) return null;

  const gateway = gatewaySnap.data() as GatewayDoc;
  if (gateway.status === "REVOKED") return null;
  if (!safeHexEqual(gateway.tokenHash, tokenHash)) return null;

  return {
    tenantId: token.tenantId,
    gatewayId: token.gatewayId,
    tokenHash,
    gateway,
  };
}

/** Admin APIs require a Firebase ID token carrying the `admin` custom claim. */
export async function verifyAdmin(req: Request): Promise<{ uid: string }> {
  const token = bearerToken(req);
  if (!token) throw new HttpError(401, "UNAUTHENTICATED", "Admin bearer token required");

  try {
    const decoded = await auth.verifyIdToken(token);
    const claims = decoded as unknown as Record<string, unknown>;
    if (claims.admin !== true) {
      throw new HttpError(403, "FORBIDDEN", "Admin custom claim required");
    }
    return { uid: decoded.uid };
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(401, "UNAUTHENTICATED", "Invalid admin token");
  }
}
