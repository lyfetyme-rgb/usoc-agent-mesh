/**
 * H-LIFT signed assertion issuer.
 *
 * H-LIFT verifies a compact HS256 JWT carried in the `hlift_assertion` cookie
 * (see h-lift/src/lib/identity.ts → verifyAssertion). That verifier requires:
 *   - header.alg === "HS256"
 *   - base64url HMAC-SHA256 over `base64url(header).base64url(payload)`
 *   - optional exp/nbf and optional iss/aud (checked when H-LIFT configures them)
 *
 * Only `sub` establishes identity. `email` and `role` are informational: H-LIFT
 * resolves roles and capabilities from its own principal tables, so a claim
 * minted here can never grant authority on its own.
 */
import { createHmac } from "node:crypto";

const SECRET_ENV = "HLIFT_IDP_HMAC_SECRET";
const ISSUER_ENV = "HLIFT_IDP_ISSUER";
const AUDIENCE_ENV = "HLIFT_IDP_AUDIENCE";
const DOMAIN_ENV = "HLIFT_COOKIE_DOMAIN";
const TTL_ENV = "HLIFT_ASSERTION_TTL_SECONDS";

const DEFAULT_TTL_SECONDS = 3600;

export const ASSERTION_COOKIE = "hlift_assertion";
export const LEGACY_SUBJECT_COOKIE = "hlift_subject";

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} must be configured to issue H-LIFT assertions`);
  return value;
}

/** Invalid or missing TTL falls back to the safe default rather than failing open. */
function ttlSeconds(): number {
  const raw = process.env[TTL_ENV]?.trim();
  if (!raw) return DEFAULT_TTL_SECONDS;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : DEFAULT_TTL_SECONDS;
}

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

/**
 * Signs the assertion. Resolve env at call time (not module load) so importing
 * this module never requires production secrets to be present.
 *
 * @param nowSeconds Epoch seconds. Override only for deterministic tests.
 */
export function signHliftAssertion(
  subject: string,
  email?: string,
  role?: string,
  nowSeconds?: number,
): string {
  const secret = requiredEnv(SECRET_ENV);
  const issuer = requiredEnv(ISSUER_ENV);
  const audience = requiredEnv(AUDIENCE_ENV);
  const sub = subject.trim();
  if (!sub) throw new Error("An H-LIFT assertion requires a non-empty subject");

  const now = nowSeconds ?? Math.floor(Date.now() / 1000);
  const header = encode({ alg: "HS256", typ: "JWT" });
  const payload = encode({
    sub,
    ...(email ? { email } : {}),
    ...(role ? { role } : {}),
    iss: issuer,
    aud: audience,
    iat: now,
    nbf: now,
    exp: now + ttlSeconds(),
  });

  const signature = createHmac("sha256", secret)
    .update(`${header}.${payload}`)
    .digest("base64url");
  return `${header}.${payload}.${signature}`;
}

/**
 * Set-Cookie values for the assertion and for clearing the legacy lab cookie.
 * Domain is only emitted when explicitly configured for a shared parent domain.
 */
export function assertionCookies(token: string): string[] {
  const domain = process.env[DOMAIN_ENV]?.trim();
  const attrs = (maxAge: number): string[] => [
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${maxAge}`,
    ...(domain ? [`Domain=${domain}`] : []),
  ];

  return [
    `${ASSERTION_COOKIE}=${token}; ${attrs(ttlSeconds()).join("; ")}`,
    `${LEGACY_SUBJECT_COOKIE}=; ${attrs(0).join("; ")}`,
  ];
}
