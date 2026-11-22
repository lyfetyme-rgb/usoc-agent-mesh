import Twilio from "twilio";
import { config } from "../config";

let cachedClient: ReturnType<typeof Twilio> | null = null;

function getClient(): ReturnType<typeof Twilio> {
  const { accountSid, authToken } = config.twilio;
  if (!accountSid || !authToken) throw new Error("Twilio credentials are not configured");
  if (!cachedClient) cachedClient = Twilio(accountSid, authToken);
  return cachedClient;
}

/** Sends a single SMS. Kept behind an interface so triggers remain testable. */
export async function sendSms(to: string, body: string): Promise<void> {
  const from = config.twilio.fromNumber;
  if (!from) throw new Error("TWILIO_FROM_NUMBER is not configured");
  await getClient().messages.create({ to, from, body });
}
