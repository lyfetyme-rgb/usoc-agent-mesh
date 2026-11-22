import { createHash } from "node:crypto";

/**
 * Minimal structured logging for Cloud Functions. Google Cloud Error Reporting
 * and log-based metrics ingest these JSON lines without an extra vendor, and a
 * request id makes it possible to reconstruct one telemetry ingress end to end.
 */

const SECRETS = [
  /Bearer\s+[A-Za-z0-9._~+/=-]+/gi,
  /(?:token|authorization|api[_-]?key)["'=:\s]+[A-Za-z0-9._~+/=-]{8,}/gi,
  /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
  /(?:\+?\d[\d\s().-]{7,}\d)/g,
];

/** Redact tokens, emails and phone numbers before anything reaches the log. */
export function redact(input: string): string {
  return SECRETS.reduce((text, pattern) => text.replace(pattern, "[REDACTED]"), input);
}

function errorParts(error: unknown): { name: string; message: string; topFrame: string } {
  if (error instanceof Error) {
    const frames = error.stack?.split("\n").filter((line) => line.trim()) ?? [];
    return {
      name: error.name,
      message: error.message,
      topFrame: frames[1]?.trim() ?? "",
    };
  }
  return { name: typeof error, message: String(error), topFrame: "" };
}

export function errorFingerprint(source: string, error: unknown): string {
  const { name, topFrame } = errorParts(error);
  return createHash("sha256").update(`${source}:${name}:${topFrame}`).digest("hex").slice(0, 16);
}

export function logError(input: {
  source: string;
  error: unknown;
  requestId?: string;
  code?: string;
}): void {
  const { name, message, topFrame } = errorParts(input.error);
  console.error(
    JSON.stringify({
      severity: "ERROR",
      event: "error",
      source: input.source,
      request_id: input.requestId ?? "-",
      code: input.code ?? name,
      fingerprint: errorFingerprint(input.source, input.error),
      message: redact(message),
      stack: redact(topFrame),
    }),
  );
}

/** Emits a duration field that Cloud Logging can turn into p50/p95 metrics. */
export function logDuration(
  source: string,
  durationMs: number,
  fields: Record<string, unknown> = {},
): void {
  console.log(
    JSON.stringify({
      severity: "INFO",
      event: "duration",
      source,
      duration_ms: Math.round(durationMs),
      ...fields,
    }),
  );
}
