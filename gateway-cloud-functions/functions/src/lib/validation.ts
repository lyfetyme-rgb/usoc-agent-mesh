import type { Request, Response } from "express";
import { config } from "../config";
import type { NumericPayload } from "../types";

export class HttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export class PayloadTooLargeError extends HttpError {
  constructor(limit: number) {
    super(413, "PAYLOAD_TOO_LARGE", `Body must be smaller than ${limit} bytes`);
  }
}

export class ValidationError extends HttpError {
  constructor(message: string) {
    super(400, "INVALID_PAYLOAD", message);
  }
}

const METRIC_NAME = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
const MAX_METRICS = 64;

/**
 * Reads the request body as bytes and aborts as soon as the hard cap is
 * reached. Checking the raw byte count (instead of the parsed size) is what
 * makes the endpoint a true data diode: oversized payloads are never parsed.
 */
export async function readRawBody(
  req: Request,
  maxBytes: number = config.maxBodyBytes,
): Promise<Buffer> {
  const preloaded = (req as Request & { rawBody?: Buffer }).rawBody;
  if (Buffer.isBuffer(preloaded)) {
    if (preloaded.byteLength >= maxBytes) throw new PayloadTooLargeError(maxBytes);
    return preloaded;
  }

  return await new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;

    const fail = (error: Error): void => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    };

    req.on("data", (chunk: Buffer | string): void => {
      if (settled) return;
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += buffer.byteLength;
      if (size >= maxBytes) {
        // Keep the socket alive so the 413 can actually be delivered; draining
        // discards the remainder without leaving the client waiting forever.
        fail(new PayloadTooLargeError(maxBytes));
        chunks.length = 0;
        req.resume();
        return;
      }
      chunks.push(buffer);
    });
    req.on("end", (): void => {
      if (!settled) {
        settled = true;
        resolve(Buffer.concat(chunks));
      }
    });
    // A client that disconnects mid-body must not leave this promise pending
    // until the platform timeout kills the function.
    req.on("aborted", () =>
      fail(new HttpError(400, "CLIENT_ABORTED", "Request body was not fully received")),
    );
    req.on("close", () => {
      if (!settled) {
        fail(new HttpError(400, "CLIENT_ABORTED", "Request body was not fully received"));
      }
    });
    req.on("error", fail);
  });
}

/** Accepts only a flat object of finite numbers. No strings, booleans, arrays or nesting. */
export function parseNumericPayload(
  raw: Buffer,
  maxBytes: number = config.maxBodyBytes,
): NumericPayload {
  if (raw.byteLength >= maxBytes) throw new PayloadTooLargeError(maxBytes);

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new ValidationError("Body must be valid JSON");
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new ValidationError("Body must be a flat JSON object");
  }

  const readings: NumericPayload = Object.create(null) as NumericPayload;
  let count = 0;
  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (!METRIC_NAME.test(key)) {
      throw new ValidationError(`Invalid metric name "${key}"`);
    }
    if (typeof value !== "number" || !Number.isFinite(value)) {
      throw new ValidationError(`Metric "${key}" must be a finite number`);
    }
    readings[key] = value;
    count += 1;
    if (count > MAX_METRICS) {
      throw new ValidationError(`At most ${MAX_METRICS} metrics may be sent per packet`);
    }
  }

  if (count === 0) throw new ValidationError("At least one numeric metric is required");
  return readings;
}

export function header(req: Request, name: string): string | undefined {
  const value = req.headers[name.toLowerCase()];
  if (typeof value === "string") return value.trim();
  if (Array.isArray(value)) return value[0]?.trim();
  return undefined;
}

export function bearerToken(req: Request): string | undefined {
  const authorization = header(req, "authorization");
  if (!authorization) return undefined;
  const match = /^Bearer\s+(.+)$/i.exec(authorization);
  return match?.[1]?.trim();
}

/** Minimal CORS handling that keeps the handler directly awaitable in tests. */
export function applyCors(req: Request, res: Response): boolean {
  const origin = req.headers.origin;
  res.set("Access-Control-Allow-Origin", typeof origin === "string" ? origin : "*");
  res.set("Vary", "Origin");
  res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Gateway-ID, X-Gateway-Token");
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return true;
  }
  return false;
}

export function respondWithError(res: {
  status: (code: number) => { json: (body: unknown) => unknown };
}, error: unknown): void {
  if (error instanceof HttpError) {
    res.status(error.status).json({ error: error.code, message: error.message });
    return;
  }
  res.status(500).json({ error: "INTERNAL", message: "Internal server error" });
}
