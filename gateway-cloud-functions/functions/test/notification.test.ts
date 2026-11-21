import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/lib/twilio", () => ({ sendSms: vi.fn().mockResolvedValue(undefined) }));

vi.mock("../src/lib/firestore", async () => {
  const { FakeFirestore, fakePaths, fakeTimestamp } = await import("./helpers/fakeFirestore");
  return {
    db: new FakeFirestore(),
    auth: { verifyIdToken: vi.fn() },
    paths: fakePaths,
    now: () => fakeTimestamp(1_700_000_000_000),
    Timestamp: { now: () => fakeTimestamp(1_700_000_000_000) },
    FieldValue: { delete: () => ({ __fakeDelete: true }) },
  };
});

import { db } from "../src/lib/firestore";
import { resolveOnDutyPhone, sendAlertSms } from "../src/lib/notification";
import { sendSms } from "../src/lib/twilio";

beforeEach(() => {
  (db as any).store.clear();
  vi.mocked(sendSms).mockClear();
});

describe("resolveOnDutyPhone", () => {
  it("resolves the tenant's on-duty technician phone", async () => {
    (db as any).store.set("tenants/t1", { onDutyTechnicianId: "tech-1" });
    (db as any).store.set("technicians/tech-1", { phone: "+15551234567" });
    await expect(resolveOnDutyPhone("t1")).resolves.toEqual({
      phone: "+15551234567",
      technicianId: "tech-1",
    });
  });

  it("returns nothing when no technician is assigned", async () => {
    await expect(resolveOnDutyPhone("missing")).resolves.toEqual({});
  });
});

describe("sendAlertSms", () => {
  it("includes the alert message and one-tap deep link", async () => {
    (db as any).store.set("tenants/t1", { onDutyTechnicianId: "tech-1" });
    (db as any).store.set("technicians/tech-1", { phone: "+15551234567" });

    const sent = await sendAlertSms({
      tenantId: "t1",
      alertId: "breach_gw1_temp",
      kind: "CRITICAL_LIMIT",
      message: "Gateway gw1: temp=90 above max 80",
    });

    expect(sent).toBe(true);
    expect(sendSms).toHaveBeenCalledWith(
      "+15551234567",
      expect.stringContaining("Gateway gw1: temp=90 above max 80"),
    );
    expect(vi.mocked(sendSms).mock.calls[0][1]).toMatch(/\/alerts\/breach_gw1_temp/);
    expect(vi.mocked(sendSms).mock.calls[0][1]).toContain("[CRITICAL]");
  });

  it("tags customer requests and skips tenants with no phone", async () => {
    (db as any).store.set("tenants/t1", { onDutyTechnicianId: "tech-1" });
    (db as any).store.set("technicians/tech-1", { phone: "+15551234567" });
    await sendAlertSms({ tenantId: "t1", alertId: "r1", kind: "CUSTOMER_REQUEST", message: "New request" });
    expect(vi.mocked(sendSms).mock.calls[0][1]).toContain("[REQUEST]");

    await expect(
      sendAlertSms({ tenantId: "unknown", alertId: "a1", kind: "CONNECTIVITY", message: "offline" }),
    ).resolves.toBe(false);
    expect(sendSms).toHaveBeenCalledTimes(1);
  });
});
