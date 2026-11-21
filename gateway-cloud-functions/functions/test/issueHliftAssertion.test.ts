import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("firebase-functions/v2/https", () => ({ onRequest: (handler: any) => handler }));

vi.mock("../src/lib/firestore", () => ({
  auth: { verifySessionCookie: vi.fn(), verifyIdToken: vi.fn() },
  db: {},
  paths: {},
}));

import { config } from "../src/config";
import { auth } from "../src/lib/firestore";
import { issueHliftAssertion } from "../src/functions/issueHliftAssertion";

const SECRET = "endpoint-test-secret";
const UID = "firebase-uid-1";

const ENV_KEYS = [
  "HLIFT_IDP_HMAC_SECRET",
  "HLIFT_IDP_ISSUER",
  "HLIFT_IDP_AUDIENCE",
  "HLIFT_ALLOWED_SUBJECTS",
  "HLIFT_SUBJECT_MAP",
  "HLIFT_IDP_SESSION_COOKIE",
  "HLIFT_COOKIE_DOMAIN",
] as const;
const original = new Map<string, string | undefined>();

function req(options: { method?: string; cookie?: string; bearer?: string } = {}): any {
  const headers: Record<string, string> = { origin: "https://app.example.com" };
  if (options.cookie) headers.cookie = options.cookie;
  if (options.bearer) headers.authorization = `Bearer ${options.bearer}`;
  return {
    method: options.method ?? "GET",
    headers,
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
  process.env.HLIFT_SUBJECT_MAP = JSON.stringify({ [UID]: "it.a.okoro" });
  process.env.HLIFT_IDP_SESSION_COOKIE = "__session";
  delete process.env.HLIFT_COOKIE_DOMAIN;

  vi.mocked(auth.verifySessionCookie).mockReset();
  vi.mocked(auth.verifyIdToken).mockReset();
  vi.mocked(auth.verifySessionCookie).mockResolvedValue({
    uid: UID,
    email: "it@example.com",
  } as any);
  vi.mocked(auth.verifyIdToken).mockResolvedValue({ uid: UID, email: "it@example.com" } as any);
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
  it("handles CORS preflight without issuing a cookie", async () => {
    const response = res();
    await handler(req({ method: "OPTIONS" }), response);
    expect(response.statusCode).toBe(204);
    expect(response.headers["Set-Cookie"]).toBeUndefined();
  });

  it("accepts GET and POST, rejects other methods", async () => {
    for (const method of ["GET", "POST"]) {
      const response = res();
      await handler(req({ method, cookie: "__session=s" }), response);
      expect(response.statusCode).toBe(302);
    }
    const rejected = res();
    await handler(req({ method: "PUT", cookie: "__session=s" }), rejected);
    expect(rejected.statusCode).toBe(405);
  });

  it("requires an IdP credential", async () => {
    const response = res();
    await handler(req(), response);
    expect(response.statusCode).toBe(401);
    expect(response.body.error).toBe("UNAUTHENTICATED");
  });

  it("verifies the session cookie with revocation checking", async () => {
    const response = res();
    await handler(req({ cookie: "__session=session-token" }), response);
    expect(auth.verifySessionCookie).toHaveBeenCalledWith("session-token", true);
    expect(auth.verifyIdToken).not.toHaveBeenCalled();
    expect(response.statusCode).toBe(302);
  });

  it("uses a bearer ID token only when no session cookie is present", async () => {
    const response = res();
    await handler(req({ bearer: "id-token" }), response);
    expect(auth.verifyIdToken).toHaveBeenCalledWith("id-token");
    expect(auth.verifySessionCookie).not.toHaveBeenCalled();
    expect(response.statusCode).toBe(302);
  });

  it("rejects invalid credentials", async () => {
    vi.mocked(auth.verifySessionCookie).mockRejectedValue(new Error("expired"));
    const response = res();
    await handler(req({ cookie: "__session=stale" }), response);
    expect(response.statusCode).toBe(401);
  });

  it("refuses unmapped identities and malformed mapping config", async () => {
    vi.mocked(auth.verifySessionCookie).mockResolvedValue({ uid: "unknown-uid" } as any);
    const unmapped = res();
    await handler(req({ cookie: "__session=s" }), unmapped);
    expect(unmapped.statusCode).toBe(403);

    process.env.HLIFT_SUBJECT_MAP = "not-json";
    vi.mocked(auth.verifySessionCookie).mockResolvedValue({ uid: UID } as any);
    const malformed = res();
    await handler(req({ cookie: "__session=s" }), malformed);
    expect(malformed.statusCode).toBe(403);
  });

  it("refuses mapped subjects outside the allowlist", async () => {
    process.env.HLIFT_ALLOWED_SUBJECTS = "cust.k.rivera";
    const response = res();
    await handler(req({ cookie: "__session=s" }), response);
    expect(response.statusCode).toBe(403);
    expect(response.body.error).toBe("FORBIDDEN");
  });

  it("issues a verifiable assertion cookie from the verified identity", async () => {
    const response = res();
    await handler(req({ cookie: "__session=s" }), response);

    expect(response.statusCode).toBe(302);
    expect(response.redirectUrl).toBe(config.appBaseUrl);
    expect(response.headers["Cache-Control"]).toBe("no-store");

    const cookies: string[] = response.headers["Set-Cookie"];
    expect(cookies).toHaveLength(2);
    const token = cookies[0].match(/^hlift_assertion=([^;]+);/)?.[1];
    expect(token).toBeTruthy();

    const [header, payload, signature] = token!.split(".");
    expect(JSON.parse(Buffer.from(header, "base64url").toString("utf8"))).toMatchObject({
      alg: "HS256",
    });
    expect(JSON.parse(Buffer.from(payload, "base64url").toString("utf8"))).toMatchObject({
      sub: "it.a.okoro",
      email: "it@example.com",
      iss: "https://idp.example.com",
      aud: "hlift",
    });
    expect(signature).toBe(
      createHmac("sha256", SECRET).update(`${header}.${payload}`).digest("base64url"),
    );
    for (const flag of ["Path=/", "HttpOnly", "Secure", "SameSite=Lax", "Max-Age=3600"]) {
      expect(cookies[0]).toContain(flag);
    }
    expect(cookies[1]).toContain("hlift_subject=;");
    expect(cookies[1]).toContain("Max-Age=0");
  });
});
