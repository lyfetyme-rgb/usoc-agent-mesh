import { Readable } from "node:stream";
import type { Request } from "express";
import { describe, expect, it } from "vitest";
import {
  PayloadTooLargeError,
  ValidationError,
  bearerToken,
  header,
  parseNumericPayload,
  readRawBody,
} from "../src/lib/validation";

function streamRequest(chunks: Buffer[]): Request {
  const stream = Readable.from(chunks);
  return {
    headers: {},
    on: stream.on.bind(stream),
    destroy: stream.destroy.bind(stream),
  } as unknown as Request;
}

describe("parseNumericPayload", () => {
  it("accepts a flat object of finite numbers", () => {
    const result = parseNumericPayload(Buffer.from('{"temp":72.5,"vibration":3}'), 4096);
    expect(result).toEqual({ temp: 72.5, vibration: 3 });
  });

  it("rejects payloads at or above the byte cap", () => {
    const raw = Buffer.alloc(4096, 0x20);
    expect(() => parseNumericPayload(raw, 4096)).toThrow(PayloadTooLargeError);
  });

  it("rejects strings, booleans, nulls, arrays and nested objects", () => {
    for (const body of [
      '{"temp":"72"}',
      '{"temp":true}',
      '{"temp":null}',
      '{"temp":[1]}',
      '{"temp":{"value":1}}',
    ]) {
      expect(() => parseNumericPayload(Buffer.from(body), 4096)).toThrow(ValidationError);
    }
  });

  it("rejects non-finite numbers such as 1e400", () => {
    expect(() => parseNumericPayload(Buffer.from('{"temp":1e400}'), 4096)).toThrow(ValidationError);
  });

  it("rejects empty bodies, invalid JSON and too many metrics", () => {
    expect(() => parseNumericPayload(Buffer.from("{}"), 4096)).toThrow(ValidationError);
    expect(() => parseNumericPayload(Buffer.from("not json"), 4096)).toThrow(ValidationError);
    const many = JSON.stringify(Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`m${i}`, i])));
    expect(() => parseNumericPayload(Buffer.from(many), 4096)).toThrow(ValidationError);
  });

  it("rejects unsafe metric names", () => {
    expect(() => parseNumericPayload(Buffer.from('{"__proto__":1}'), 4096)).toThrow(ValidationError);
    expect(() => parseNumericPayload(Buffer.from('{"1bad":1}'), 4096)).toThrow(ValidationError);
  });
});

describe("readRawBody", () => {
  it("uses the preloaded rawBody when present", async () => {
    const req = { rawBody: Buffer.from('{"temp":1}'), headers: {} } as Request;
    await expect(readRawBody(req, 4096)).resolves.toEqual(Buffer.from('{"temp":1}'));
  });

  it("rejects an oversized preloaded body", async () => {
    const req = { rawBody: Buffer.alloc(4096), headers: {} } as Request;
    await expect(readRawBody(req, 4096)).rejects.toThrow(PayloadTooLargeError);
  });

  it("reads a streamed body within the limit", async () => {
    const req = streamRequest([Buffer.from('{"a":'), Buffer.from("1}")]);
    await expect(readRawBody(req, 4096)).resolves.toEqual(Buffer.from('{"a":1}'));
  });

  it("aborts a streamed body once the limit is reached", async () => {
    const req = streamRequest([Buffer.alloc(4096)]);
    await expect(readRawBody(req, 4096)).rejects.toThrow(PayloadTooLargeError);
  });
});

describe("header helpers", () => {
  it("reads and trims headers case-insensitively", () => {
    const req = { headers: { "x-gateway-id": "  gw-1  " } } as Request;
    expect(header(req, "X-Gateway-ID")).toBe("gw-1");
  });

  it("extracts bearer tokens only", () => {
    const req = { headers: { authorization: "Bearer abc123" } } as Request;
    expect(bearerToken(req)).toBe("abc123");
    const other = { headers: { authorization: "Basic abc123" } } as Request;
    expect(bearerToken(other)).toBeUndefined();
  });
});
