import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("firebase-functions/v2/firestore", () => ({
  onDocumentCreated: (_path: string, handler: any) => handler,
}));

const NOW = 1_700_000_000_000;

vi.mock("../src/lib/firestore", async () => {
  const { FakeFirestore, fakeTimestamp } = await import("./helpers/fakeFirestore");
  return {
    db: new FakeFirestore(),
    now: () => fakeTimestamp(NOW),
    FieldValue: { delete: () => ({ __fakeDelete: true }) },
  };
});

vi.mock("../src/lib/notification", () => ({ sendAlertSms: vi.fn().mockResolvedValue(true) }));

import { db } from "../src/lib/firestore";
import { sendAlertSms } from "../src/lib/notification";
import {
  dispatchAlertNotification,
  dispatchCustomerRequestNotification,
} from "../src/functions/dispatchAlertNotification";

function event(data: any, alertId: string): any {
  const path = `alerts/${alertId}`;
  (db as any).store.set(path, data);
  return {
    data: { data: () => data, ref: (db as any).doc(path) },
    params: { alertId, requestId: alertId },
  };
}

beforeEach(() => {
  (db as any).store.clear();
  vi.mocked(sendAlertSms).mockClear();
  vi.mocked(sendAlertSms).mockResolvedValue(true);
});

describe("dispatchAlertNotification", () => {
  it("claims the alert before sending and records notifiedAt", async () => {
    const evt = event(
      {
        tenantId: "t1",
        kind: "CRITICAL_LIMIT",
        status: "OPEN",
        message: "Gateway gw1: temp=90 above max 80",
      },
      "breach_gw1_temp",
    );

    await (dispatchAlertNotification as any)(evt);

    expect(sendAlertSms).toHaveBeenCalledWith({
      tenantId: "t1",
      alertId: "breach_gw1_temp",
      kind: "CRITICAL_LIMIT",
      message: "Gateway gw1: temp=90 above max 80",
    });
    expect((db as any).store.get("alerts/breach_gw1_temp").notifiedAt.toMillis()).toBe(NOW);
  });

  it("does not resend an already-notified or non-OPEN alert", async () => {
    await (dispatchAlertNotification as any)(
      event({ tenantId: "t1", status: "OPEN", notifiedAt: {}, message: "offline" }, "a1"),
    );
    await (dispatchAlertNotification as any)(
      event({ tenantId: "t1", status: "RESOLVED", message: "offline" }, "a2"),
    );
    expect(sendAlertSms).not.toHaveBeenCalled();
  });

  it("does not mark notified when no SMS could be sent", async () => {
    vi.mocked(sendAlertSms).mockResolvedValue(false);
    const evt = event({ tenantId: "t1", status: "OPEN", message: "offline" }, "a1");
    await (dispatchAlertNotification as any)(evt);
    expect((db as any).store.get("alerts/a1").notifiedAt).toBeUndefined();
  });

  it("releases the claim and rethrows when Twilio fails, so the trigger can retry", async () => {
    vi.mocked(sendAlertSms).mockRejectedValueOnce(new Error("Twilio 503"));
    const evt = event({ tenantId: "t1", status: "OPEN", message: "offline" }, "a1");

    await expect((dispatchAlertNotification as any)(evt)).rejects.toThrow("Twilio 503");
    expect((db as any).store.get("alerts/a1").notifiedAt).toBeUndefined();

    vi.mocked(sendAlertSms).mockResolvedValueOnce(true);
    await (dispatchAlertNotification as any)(evt);
    expect(sendAlertSms).toHaveBeenCalledTimes(2);
    expect((db as any).store.get("alerts/a1").notifiedAt.toMillis()).toBe(NOW);
  });
});

describe("dispatchCustomerRequestNotification", () => {
  it("dispatches a request notification with the subject", async () => {
    const evt = event({ tenantId: "t1", subject: "Leaking valve" }, "req-1");
    await (dispatchCustomerRequestNotification as any)(evt);

    expect(sendAlertSms).toHaveBeenCalledWith({
      tenantId: "t1",
      alertId: "req-1",
      kind: "CUSTOMER_REQUEST",
      message: "New Customer Request Form received: Leaking valve",
    });
    expect((db as any).store.get("alerts/req-1").notifiedAt.toMillis()).toBe(NOW);
  });

  it("ignores requests without a tenant", async () => {
    await (dispatchCustomerRequestNotification as any)(event({ subject: "x" }, "req-2"));
    expect(sendAlertSms).not.toHaveBeenCalled();
  });
});
