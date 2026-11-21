/** Runtime configuration. All values can be overridden through environment variables. */

function strEnv(name: string, fallback: string): string {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  return raw.trim();
}

function intEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}

export const config = {
  appBaseUrl: strEnv("APP_BASE_URL", "https://app.example.com").replace(/\/+$/, ""),
  appDeepLinkScheme: strEnv("APP_DEEP_LINK_SCHEME", "").replace(/:\/*$/, ""),

  maxBodyBytes: intEnv("TELEMETRY_MAX_BODY_BYTES", 4096),
  ttlDays: intEnv("TELEMETRY_TTL_DAYS", 30),
  offlineThresholdMs: intEnv("GATEWAY_OFFLINE_THRESHOLD_MS", 180_000),
  heartbeatSchedule: strEnv("HEARTBEAT_SCHEDULE", "every 1 minute"),
  breachAlertCooldownMs: intEnv("BREACH_ALERT_COOLDOWN_MS", 300_000),

  twilio: {
    accountSid: strEnv("TWILIO_ACCOUNT_SID", ""),
    authToken: strEnv("TWILIO_AUTH_TOKEN", ""),
    fromNumber: strEnv("TWILIO_FROM_NUMBER", ""),
  },
  alertFallbackPhone: strEnv("ALERT_FALLBACK_PHONE", ""),
} as const;

export const TTL_MS = config.ttlDays * 24 * 60 * 60 * 1000;
