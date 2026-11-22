import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("firebase-functions/v2/firestore", () => ({
  onDocumentCreated: (_path: string, handler: any) => handler,
}));

const NOW = 1_700_000_000_000;

vi.mock("../src/lib/firestore", async () => {
  const { fakeTimestamp } = await import("./helpers/fakeFirestore");
  return { now: () => fakeTimestamp(NOW) };
});

vi.mock("../src/lib/notification", () => ({ sendAlertSms: vi.fn().mockResolvedValue(true) }));

import { sendAlertSms } from "../src/lib/notification";
import {
  dispatchAlertNotification,
  dispatchCustomerRequestNotification,
} from "../src/functions/dispatchAlertNotification";

function event(data: any, alertId: string): any {
  const update = vi.fn().mockResolvedValue({});
  return {
    data: { data: () => data, ref: { update } },
    params: { alertId, requestId: alertId },
    update,
  };
}

beforeEach(() => {
  vi.mocked(sendAlertSms).mockClear();
  vi.mocked(sendAlertSms).mockResolvedValue(true);
});

describe("dispatchAlertNotification", () => {
  it("texts on-duty for a new alert and records notifiedAt", async () => {
    const evt = event(
      { tenantId: "t1", kind: "CRITICAL_LIMIT", message: "Gateway gw1: temp=90 above max 80" },
      "breach_gw1_temp",
    );

    await (dispatchAlertNotification as any)(evt);

    expect(sendAlertSms).toHaveBeenCalledWith({
      tenantId: "t1",
      alertId: "breach_gw1_temp",
      kind: "CRITICAL_LIMIT",
      message: "Gateway gw1: temp=90 above max 80",
    });
    expect(evt.update).toHaveBeenCalledTimes(1);
    expect(evt.update.mock.calls[0][0].notifiedAt.toMillis()).toBe(NOW);
  });

  it("does not resend an already-notified alert", async () => {
    const evt = event({ tenantId: "t1", kind: "CONNECTIVITY", notifiedAt: {}, message: "offline" }, "a1");
    await (dispatchAlertNotification as any)(evt);
    expect(sendAlertSms).not.toHaveBeenCalled();
  });

  it("does not mark notified when no SMS could be sent", async () => {
    vi.mocked(sendAlertSms).mockResolvedValue(false);
    const evt = event({ tenantId: "t1", kind: "CONNECTIVITY", message: "offline" }, "a1");
    await (dispatchAlertNotification as any)(evt);
    expect(evt.update).not.toHaveBeenCalled();
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
    expect(evt.update).toHaveBeenCalled();
  });

  it("ignores requests without a tenant", async () => {
    await (dispatchCustomerRequestNotification as any)(event({ subject: "x" }, "req-2"));
    expect(sendAlertSms).not.toHaveBeenCalled();
  });
});
