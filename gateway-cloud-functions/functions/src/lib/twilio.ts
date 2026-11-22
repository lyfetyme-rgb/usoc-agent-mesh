import Twilio from "twilio";
import { config } from "../config";

/** Bounded so a hung provider call cannot pin a Cloud Function until timeout. */
const SEND_TIMEOUT_MS = 10_000;

let cachedClient: ReturnType<typeof Twilio> | null = null;

export class TwilioConfigError extends Error {
  readonly code = "TWILIO_NOT_CONFIGURED";
}

function getClient(): ReturnType<typeof Twilio> {
  const { accountSid, authToken } = config.twilio;
  if (!accountSid || !authToken) throw new TwilioConfigError("Twilio credentials are not configured");
  if (!cachedClient) cachedClient = Twilio(accountSid, authToken, { timeout: SEND_TIMEOUT_MS });
  return cachedClient;
}

/** Sends a single SMS. Kept behind an interface so triggers remain testable. */
export async function sendSms(to: string, body: string): Promise<void> {
  const from = config.twilio.fromNumber;
  if (!from) throw new TwilioConfigError("TWILIO_FROM_NUMBER is not configured");
  await getClient().messages.create({ to, from, body });
}
