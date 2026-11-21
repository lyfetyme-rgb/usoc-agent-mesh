import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("firebase-functions/v2/https", () => ({ onRequest: (handler: any) => handler }));

vi.mock("../src/lib/firestore", () => ({
  auth: { verifyIdToken: vi.fn() },
  db: {},
  paths: {},
}));

import { config } from "../src/config";
import { auth } from "../src/lib/firestore";
import { issueHliftAssertion } from "../src/functions/issueHliftAssertion";

const SECRET = "endpoint-test-secret";

const ENV_KEYS = [
  "HLIFT_IDP_HMAC_SECRET",
  "HLIFT_IDP_ISSUER",
  "HLIFT_IDP_AUDIENCE",
  "HLIFT_ALLOWED_SUBJECTS",
  "HLIFT_COOKIE_DOMAIN",
] as const;
const original = new Map<string, string | undefined>();

function req(body?: unknown, method = "POST", admin = true): any {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    origin: "https://admin.example.com",
  };
  if (admin) headers.authorization = "Bearer admin-token";
  return {
    method,
    headers,
    rawBody: Buffer.isBuffer(body) ? body : Buffer.from(JSON.stringify(body ?? {})),
    on: () => undefined,
    destroy: () => undefined,
  };
}

function res(): any {
  const headers: Record<string, any> = {};
  return {
    statusCode: 200,
    body: undefined,
    headers,
    redirectUrl: undefined as string | undefined,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(body: any) {
      this.body = body;
      return this;
    },
    set(key: string, value: string) {
      headers[key] = value;
      return this;
    },
    setHeader(key: string, value: any) {
      headers[key] = value;
      return this;
    },
    getHeader(key: string) {
      return headers[key];
    },
    redirect(code: number, url: string) {
      this.statusCode = code;
      this.redirectUrl = url;
      return this;
    },
    end() {
      return this;
    },
  };
}

beforeEach(() => {
  for (const key of ENV_KEYS) original.set(key, process.env[key]);
  process.env.HLIFT_IDP_HMAC_SECRET = SECRET;
  process.env.HLIFT_IDP_ISSUER = "https://idp.example.com";
  process.env.HLIFT_IDP_AUDIENCE = "hlift";
  process.env.HLIFT_ALLOWED_SUBJECTS = "it.a.okoro,cust.k.rivera";
  delete process.env.HLIFT_COOKIE_DOMAIN;
  vi.mocked(auth.verifyIdToken).mockReset();
  vi.mocked(auth.verifyIdToken).mockResolvedValue({ uid: "admin-1", admin: true } as any);
});

afterEach(() => {
  for (const [key, value] of original) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  original.clear();
});

const handler = issueHliftAssertion as any;

describe("issueHliftAssertion", () => {
  it("rejects CORS preflight without issuing a cookie", async () => {
    const response = res();
    await handler(req(undefined, "OPTIONS"), response);
    expect(response.statusCode).toBe(204);
    expect(response.headers["Set-Cookie"]).toBeUndefined();
  });

  it("rejects non-POST methods", async () => {
    const response = res();
    await handler(req(undefined, "GET"), response);
    expect(response.statusCode).toBe(405);
    expect(response.body).toEqual({ error: "METHOD_NOT_ALLOWED" });
  });

  it("requires an authenticated admin", async () => {
    const response = res();
    await handler(req({ subject: "it.a.okoro" }, "POST", false), response);
    expect(response.statusCode).toBe(401);

    vi.mocked(auth.verifyIdToken).mockResolvedValue({ uid: "u", admin: false } as any);
    const forbidden = res();
    await handler(req({ subject: "it.a.okoro" }), forbidden);
    expect(forbidden.statusCode).toBe(403);
  });

  it("refuses subjects outside the allowlist", async () => {
    const response = res();
    await handler(req({ subject: "attacker" }), response);
    expect(response.statusCode).toBe(403);
    expect(response.body).toEqual({
      error: "FORBIDDEN",
      message: "Subject is not an H-LIFT principal",
    });
    expect(response.headers["Set-Cookie"]).toBeUndefined();
  });

  it("rejects malformed or unexpected payload shapes", async () => {
    const malformed = res();
    await handler(req(Buffer.from("{not json")), malformed);
    expect(malformed.statusCode).toBe(400);

    const extra = res();
    await handler(req({ subject: "it.a.okoro", role: "ADMIN" }), extra);
    expect(extra.statusCode).toBe(400);
  });

  it("issues a verifiable assertion cookie and redirects to the app", async () => {
    const response = res();
    await handler(req({ subject: "it.a.okoro" }), response);

    expect(response.statusCode).toBe(302);
    expect(response.redirectUrl).toBe(config.appBaseUrl);
    expect(response.headers["Cache-Control"]).toBe("no-store");

    const cookies: string[] = response.headers["Set-Cookie"];
    expect(cookies).toHaveLength(2);
    const assertion = cookies[0];
    const token = assertion.match(/^hlift_assertion=([^;]+);/)?.[1];
    expect(token).toBeTruthy();

    // Independently verify the signature the way H-LIFT does.
    const [header, payload, signature] = token!.split(".");
    expect(JSON.parse(Buffer.from(header, "base64url").toString("utf8"))).toMatchObject({
      alg: "HS256",
    });
    expect(JSON.parse(Buffer.from(payload, "base64url").toString("utf8"))).toMatchObject({
      sub: "it.a.okoro",
      iss: "https://idp.example.com",
      aud: "hlift",
    });
    expect(signature).toBe(
      createHmac("sha256", SECRET).update(`${header}.${payload}`).digest("base64url"),
    );
    expect(assertion).toContain("HttpOnly");
    expect(assertion).toContain("Secure");
    expect(assertion).toContain("SameSite=Lax");
    expect(cookies[1]).toContain("hlift_subject=;");
    expect(cookies[1]).toContain("Max-Age=0");
  });
});
