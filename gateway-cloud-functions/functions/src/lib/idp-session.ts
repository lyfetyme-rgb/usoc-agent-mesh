/**
 * IdP identity resolution for the H-LIFT assertion callback.
 *
 * A browser callback cannot attach an Authorization header, so the verified
 * identity comes from the IdP session cookie (Firebase `__session` by default).
 * A bearer ID token is still accepted for server-to-server automation. Both are
 * verified by Firebase Admin — nothing is trusted from the request body.
 *
 * The verified uid must be explicitly mapped to an H-LIFT subject. An unmapped
 * identity cannot obtain an assertion, even if it holds a valid Firebase token.
 */
import type { Request } from "express";
import { auth } from "./firestore";
import { HttpError, bearerToken } from "./validation";

const SESSION_COOKIE_ENV = "HLIFT_IDP_SESSION_COOKIE";
const SUBJECT_MAP_ENV = "HLIFT_SUBJECT_MAP";
const DEFAULT_SESSION_COOKIE = "__session";

export interface IdpIdentity {
  uid: string;
  subject: string;
  email?: string;
}

function parseCookies(raw: string | undefined): Record<string, string> {
  const cookies: Record<string, string> = {};
  for (const part of (raw ?? "").split(";")) {
    const idx = part.indexOf("=");
    if (idx <= 0) continue;
    const name = part.slice(0, idx).trim();
    if (!name) continue;
    try {
      cookies[name] = decodeURIComponent(part.slice(idx + 1).trim());
    } catch {
      cookies[name] = part.slice(idx + 1).trim();
    }
  }
  return cookies;
}

/** `{"firebase-uid": "it.a.okoro", ...}`; malformed config resolves to no mappings. */
function subjectMap(): Map<string, string> {
  const raw = process.env[SUBJECT_MAP_ENV]?.trim();
  if (!raw) return new Map();
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return new Map();
    const entries = Object.entries(parsed as Record<string, unknown>)
      .filter((entry): entry is [string, string] =>
        typeof entry[0] === "string" && Boolean(entry[0]) && typeof entry[1] === "string" && Boolean(entry[1]),
      )
      .map(([uid, subject]) => [uid, subject.trim()] as [string, string])
      .filter(([, subject]) => Boolean(subject));
    return new Map(entries);
  } catch {
    return new Map();
  }
}

/** Resolves a principal from verified IdP credentials only. */
export async function resolveIdpIdentity(req: Request): Promise<IdpIdentity> {
  const cookieName = process.env[SESSION_COOKIE_ENV]?.trim() || DEFAULT_SESSION_COOKIE;
  const cookieToken = parseCookies(req.headers.cookie as string | undefined)[cookieName];
  const bearer = bearerToken(req);
  const token = cookieToken || bearer;
  if (!token) throw new HttpError(401, "UNAUTHENTICATED", "IdP session or bearer token required");

  let claims: { uid: string; email?: string };
  try {
    claims = cookieToken
      ? await auth.verifySessionCookie(cookieToken, true)
      : await auth.verifyIdToken(token);
  } catch {
    throw new HttpError(401, "UNAUTHENTICATED", "Invalid or expired IdP credential");
  }

  const subject = subjectMap().get(claims.uid);
  if (!subject) throw new HttpError(403, "FORBIDDEN", "Identity is not mapped to an H-LIFT principal");

  return {
    uid: claims.uid,
    subject,
    ...(typeof claims.email === "string" ? { email: claims.email } : {}),
  };
}
