import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ASSERTION_COOKIE,
  LEGACY_SUBJECT_COOKIE,
  assertionCookies,
  signHliftAssertion,
} from "../src/lib/hlift-assertion";

const SECRET = "test-shared-secret";
const ISSUER = "https://idp.example.com";
const AUDIENCE = "hlift";
const NOW = 1_700_000_000;

const ENV_KEYS = [
  "HLIFT_IDP_HMAC_SECRET",
  "HLIFT_IDP_ISSUER",
  "HLIFT_IDP_AUDIENCE",
  "HLIFT_COOKIE_DOMAIN",
  "HLIFT_ASSERTION_TTL_SECONDS",
] as const;

const original = new Map<string, string | undefined>();

beforeEach(() => {
  for (const key of ENV_KEYS) original.set(key, process.env[key]);
  process.env.HLIFT_IDP_HMAC_SECRET = SECRET;
  process.env.HLIFT_IDP_ISSUER = ISSUER;
  process.env.HLIFT_IDP_AUDIENCE = AUDIENCE;
  delete process.env.HLIFT_COOKIE_DOMAIN;
  delete process.env.HLIFT_ASSERTION_TTL_SECONDS;
});

afterEach(() => {
  for (const [key, value] of original) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  original.clear();
});

function decode(part: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

describe("signHliftAssertion", () => {
  it("produces an HS256 JWT H-LIFT's verifier will accept", () => {
    const token = signHliftAssertion("it.a.okoro", "it@example.com", "IT_ADMIN", NOW);
    const [header, payload, signature] = token.split(".");

    expect(decode(header)).toEqual({ alg: "HS256", typ: "JWT" });
    expect(decode(payload)).toEqual({
      sub: "it.a.okoro",
      email: "it@example.com",
      role: "IT_ADMIN",
      iss: ISSUER,
      aud: AUDIENCE,
      iat: NOW,
      nbf: NOW,
      exp: NOW + 3600,
    });
    expect(signature).toBe(
      createHmac("sha256", SECRET).update(`${header}.${payload}`).digest("base64url"),
    );
    expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  });

  it("omits optional identity claims when they are not supplied", () => {
    const [header, payload] = signHliftAssertion("cust.k.rivera", undefined, undefined, NOW).split(".");
    expect(decode(header).alg).toBe("HS256");
    expect(decode(payload)).not.toHaveProperty("email");
    expect(decode(payload)).not.toHaveProperty("role");
    expect(decode(payload).sub).toBe("cust.k.rivera");
  });

  it("respects a configured TTL and falls back on invalid values", () => {
    process.env.HLIFT_ASSERTION_TTL_SECONDS = "120";
    let token = signHliftAssertion("it.a.okoro", undefined, undefined, NOW);
    expect(Number(decode(token.split(".")[1]).exp)).toBe(NOW + 120);

    process.env.HLIFT_ASSERTION_TTL_SECONDS = "not-a-number";
    token = signHliftAssertion("it.a.okoro", undefined, undefined, NOW);
    expect(Number(decode(token.split(".")[1]).exp)).toBe(NOW + 3600);
  });

  it("fails closed when signing configuration is missing", () => {
    delete process.env.HLIFT_IDP_HMAC_SECRET;
    expect(() => signHliftAssertion("it.a.okoro")).toThrow(/HLIFT_IDP_HMAC_SECRET/);

    process.env.HLIFT_IDP_HMAC_SECRET = SECRET;
    delete process.env.HLIFT_IDP_ISSUER;
    expect(() => signHliftAssertion("it.a.okoro")).toThrow(/HLIFT_IDP_ISSUER/);

    process.env.HLIFT_IDP_ISSUER = ISSUER;
    delete process.env.HLIFT_IDP_AUDIENCE;
    expect(() => signHliftAssertion("it.a.okoro")).toThrow(/HLIFT_IDP_AUDIENCE/);
  });

  it("rejects an empty subject", () => {
    expect(() => signHliftAssertion("   ")).toThrow(/non-empty subject/);
  });
});

describe("assertionCookies", () => {
  it("sets a hardened assertion cookie and clears the legacy lab cookie", () => {
    const [assertion, legacy] = assertionCookies("a.b.c");

    expect(assertion.startsWith(`${ASSERTION_COOKIE}=a.b.c;`)).toBe(true);
    for (const flag of ["Path=/", "HttpOnly", "Secure", "SameSite=Lax", "Max-Age=3600"]) {
      expect(assertion).toContain(flag);
    }
    expect(assertion).not.toContain("Domain=");

    expect(legacy.startsWith(`${LEGACY_SUBJECT_COOKIE}=;`)).toBe(true);
    expect(legacy).toContain("Max-Age=0");
    expect(legacy).toContain("HttpOnly");
    expect(legacy).toContain("Secure");
  });

  it("adds Domain only when configured for a shared parent domain", () => {
    process.env.HLIFT_COOKIE_DOMAIN = "example.com";
    const [assertion] = assertionCookies("a.b.c");
    expect(assertion).toContain("Domain=example.com");
  });
});
