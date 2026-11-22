import { beforeEach, describe, expect, it, vi } from "vitest";

const { create, twilioClient } = vi.hoisted(() => {
  const create = vi.fn().mockResolvedValue({ sid: "SM123" });
  const twilioClient = vi.fn(() => ({ messages: { create } }));
  return { create, twilioClient };
});

vi.mock("twilio", () => ({ default: twilioClient }));

vi.mock("../src/config", () => ({
  config: {
    twilio: {
      accountSid: "AC123",
      authToken: "token123",
      fromNumber: "+15550000000",
    },
  },
}));

import { sendSms, TwilioConfigError } from "../src/lib/twilio";

beforeEach(() => {
  create.mockClear();
  twilioClient.mockClear();
});

describe("sendSms", () => {
  it("configures a bounded timeout on the Twilio client", async () => {
    await sendSms("+15551234567", "Alert");
    expect(twilioClient).toHaveBeenCalledWith("AC123", "token123", { timeout: 10_000 });
    expect(create).toHaveBeenCalledWith({
      to: "+15551234567",
      from: "+15550000000",
      body: "Alert",
    });
  });

  it("fails fast with a stable code when Twilio is not configured", async () => {
    const { config } = await import("../src/config");
    const original = config.twilio.fromNumber;
    (config.twilio as { fromNumber?: string }).fromNumber = undefined;
    await expect(sendSms("+15551234567", "Alert")).rejects.toBeInstanceOf(TwilioConfigError);
    (config.twilio as { fromNumber?: string }).fromNumber = original;
  });
});
