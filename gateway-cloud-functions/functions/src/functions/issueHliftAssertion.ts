import { onRequest } from "firebase-functions/v2/https";
import { z } from "zod";
import { config } from "../config";
import { verifyAdmin } from "../lib/auth";
import { assertionCookies, signHliftAssertion } from "../lib/hlift-assertion";
import { HttpError, applyCors, readRawBody, respondWithError } from "../lib/validation";

const requestSchema = z.object({ subject: z.string().min(1).max(128) }).strict();
const MAX_BODY_BYTES = 4096;

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
 * Issues the `hlift_assertion` cookie consumed by H-LIFT's signed-assertion
 * mode, then redirects to the app so the browser sends the cookie on load.
 *
 * verifyAdmin() is an authentication stand-in for this pilot. Replace it with
 * the real IdP callback verification (ID token / session) before production;
 * the signing and cookie contract below does not change.
 */
export const issueHliftAssertion = onRequest(async (req, res) => {
  if (applyCors(req, res)) return;

  if (req.method !== "POST") {
    res.set("Allow", "POST").status(405).json({ error: "METHOD_NOT_ALLOWED" });
    return;
  }

  try {
    await verifyAdmin(req);

    const raw = await readRawBody(req, MAX_BODY_BYTES);
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw.toString("utf8"));
    } catch {
      throw new HttpError(400, "INVALID_PAYLOAD", "Body must be valid JSON");
    }
    const body = requestSchema.parse(parsed);

    if (!allowedSubjects().has(body.subject)) {
      throw new HttpError(403, "FORBIDDEN", "Subject is not an H-LIFT principal");
    }

    const token = signHliftAssertion(body.subject);
    res.set("Cache-Control", "no-store");
    res.setHeader("Set-Cookie", assertionCookies(token));
    res.redirect(302, config.appBaseUrl);
  } catch (error) {
    if (error instanceof z.ZodError) {
      respondWithError(res, new HttpError(400, "INVALID_PAYLOAD", "Invalid subject payload"));
      return;
    }
    respondWithError(res, error);
  }
});
