import { describe, expect, it } from "vitest";
import {
  alertDeepLink,
  breachAlertId,
  connectivityAlertId,
  connectivityMessage,
  customerRequestMessage,
  dedupeKey,
  describeBreach,
} from "../src/lib/alerts";

describe("alert identity helpers", () => {
  it("builds stable, sanitized IDs", () => {
    expect(breachAlertId("gw/1", "temp.hi")).toBe("breach_gw_2f1_temp_2ehi");
    expect(connectivityAlertId("gw-1")).toBe("connectivity_gw-1");
    expect(dedupeKey("CRITICAL_LIMIT", "gw-1", "temp")).toBe("CRITICAL_LIMIT:gw-1:temp");
  });

  it("does not collide between dot, underscore and dash metric names", () => {
    const ids = new Set([
      breachAlertId("gw1", "temp.c"),
      breachAlertId("gw1", "temp_c"),
      breachAlertId("gw1", "temp-c"),
    ]);
    expect(ids.size).toBe(3);
  });

  it("builds a deep link with an encoded alert id", () => {
    expect(alertDeepLink("breach gw/1")).toMatch(/\/alerts\/breach%20gw%2F1/);
  });
});

describe("alert copy", () => {
  it("describes breaches with the breached bound", () => {
    expect(describeBreach("gw-1", { metric: "temp", value: 90, limit: 80, direction: "above_max" })).toBe(
      "Gateway gw-1: temp=90 above max 80",
    );
    expect(describeBreach("gw-1", { metric: "temp", value: 5, limit: 10, direction: "below_min" })).toBe(
      "Gateway gw-1: temp=5 below min 10",
    );
  });

  it("describes offline and customer request events", () => {
    expect(connectivityMessage("gw-1", 180_000)).toMatch(/OFFLINE.*3\+ min/);
    expect(customerRequestMessage("Leak")).toMatch(/Leak/);
  });
});
