import { onRequest } from "firebase-functions/v2/https";
import { config } from "../config";
import { resolveIdpIdentity } from "../lib/idp-session";
import { assertionCookies, signHliftAssertion } from "../lib/hlift-assertion";
import { logError } from "../lib/observability";
import { HttpError, applyCors, respondWithError } from "../lib/validation";

/** Fail closed: an unconfigured allowlist authorizes no principals. */
function allowedSubjects(): Set<string> {
  return new Set(
    (process.env.HLIFT_ALLOWED_SUBJECTS ?? "")
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean),
  );
}

/**
 * IdP callback: verifies the caller's IdP session (or server-to-server bearer
 * token), maps the verified uid to an H-LIFT subject, issues the
 * `hlift_assertion` cookie and redirects to the app so the browser sends it on
 * load. No identity claim is ever accepted from the request body.
 */
export const issueHliftAssertion = onRequest(async (req, res) => {
  if (applyCors(req, res)) return;
  res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");

  if (req.method !== "GET" && req.method !== "POST") {
    res.set("Allow", "GET, POST").status(405).json({ error: "METHOD_NOT_ALLOWED" });
    return;
  }

  try {
    const identity = await resolveIdpIdentity(req);
    if (!allowedSubjects().has(identity.subject)) {
      throw new HttpError(403, "FORBIDDEN", "Subject is not an H-LIFT principal");
    }

    const token = signHliftAssertion(identity.subject, identity.email);
    res.set("Cache-Control", "no-store");
    res.setHeader("Set-Cookie", assertionCookies(token));
    res.redirect(302, config.appBaseUrl);
  } catch (error) {
    logError({
      source: "issueHliftAssertion",
      error,
      code: error instanceof HttpError ? error.code : undefined,
    });
    respondWithError(res, error);
  }
});
