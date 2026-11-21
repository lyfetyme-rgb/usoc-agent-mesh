import { describe, expect, it } from "vitest";
import { buildActivationUrl, buildQrSvgDataUrl, buildQrStickerUrl } from "../src/lib/qr";

describe("QR URLs", () => {
  it("puts the token in the fragment, never in the path or query", () => {
    const url = buildActivationUrl("tenant 1", "gw-1", "raw/token?x=1");
    expect(url).toContain("/activate#");
    expect(url).not.toContain("?");
    const fragment = url.split("#")[1];
    expect(fragment).toContain("t=raw%2Ftoken%3Fx%3D1");
  });

  it("builds a printable sticker URL with the token in the fragment", () => {
    const url = buildQrStickerUrl("tenant-1", "gw-1", "tok");
    expect(url).toMatch(/\/stickers\/tenant-1\/gw-1#t=tok$/);
  });

  it("generates a real SVG data URL", async () => {
    const dataUrl = await buildQrSvgDataUrl("https://example.com/activate#t=tok");
    expect(dataUrl.startsWith("data:image/svg+xml;base64,")).toBe(true);
    const svg = Buffer.from(dataUrl.split(",")[1], "base64").toString("utf8");
    expect(svg).toContain("<svg");
  });
});
