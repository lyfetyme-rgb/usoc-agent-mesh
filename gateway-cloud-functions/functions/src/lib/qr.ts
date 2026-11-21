import QRCode from "qrcode";
import { config } from "../config";

/**
 * The raw token lives in the URL fragment only. Fragments are never sent in
 * HTTP requests, so scanning the sticker cannot leak the token to server logs.
 */
export function buildActivationUrl(tenantId: string, gatewayId: string, rawToken: string): string {
  const gateway = `${encodeURIComponent(tenantId)}:${encodeURIComponent(gatewayId)}`;
  return `${config.appBaseUrl}/activate#g=${gateway}&t=${encodeURIComponent(rawToken)}`;
}

/** Hosted, printable sticker page. The activation secret is again in the fragment. */
export function buildQrStickerUrl(tenantId: string, gatewayId: string, rawToken: string): string {
  return `${config.appBaseUrl}/stickers/${encodeURIComponent(tenantId)}/${encodeURIComponent(gatewayId)}#t=${encodeURIComponent(rawToken)}`;
}

/** Ready-to-print SVG data URL, useful when no sticker frontend is deployed. */
export async function buildQrSvgDataUrl(activationUrl: string): Promise<string> {
  const svg = await QRCode.toString(activationUrl, {
    type: "svg",
    margin: 1,
    width: 256,
    errorCorrectionLevel: "M",
  });
  return `data:image/svg+xml;base64,${Buffer.from(svg, "utf8").toString("base64")}`;
}
