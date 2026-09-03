import { describe, expect, it } from "vitest";
import {
  nextCheckAt,
  nextState,
  slotFor,
  worstStatus,
  type StateRow,
} from "../src/state.js";

const T0 = "2026-09-03T00:00:00.000Z";
const T1 = "2026-09-03T06:00:00.000Z";

describe("nextState", () => {
  it("marks a first observation as firstSeen, not changed", () => {
    const { row, changed, firstSeen } = nextState(undefined, {
      status: "warn",
      score: 70,
      observedAt: T0,
    });
    expect(firstSeen).toBe(true);
    expect(changed).toBe(false);
    expect(row).toMatchObject({ status: "warn", since: T0, consecutiveCount: 1, lastOkAt: null });
  });

  it("increments the counter when the status is unchanged", () => {
    const prev: StateRow = {
      status: "ok",
      score: 90,
      since: T0,
      lastOkAt: T0,
      consecutiveCount: 3,
    };
    const { row, changed } = nextState(prev, { status: "ok", score: 92, observedAt: T1 });
    expect(changed).toBe(false);
    expect(row.consecutiveCount).toBe(4);
    expect(row.since).toBe(T0);
    expect(row.lastOkAt).toBe(T1);
  });

  it("resets since and counter on a transition", () => {
    const prev: StateRow = {
      status: "ok",
      score: 90,
      since: T0,
      lastOkAt: T0,
      consecutiveCount: 5,
    };
    const { row, changed } = nextState(prev, { status: "crit", score: 40, observedAt: T1 });
    expect(changed).toBe(true);
    expect(row).toMatchObject({ status: "crit", since: T1, consecutiveCount: 1 });
    expect(row.lastOkAt).toBe(T0); // preserved
  });
});

describe("worstStatus", () => {
  it("ranks crit > unknown > warn > info > ok", () => {
    expect(worstStatus(["ok", "warn", "ok"])).toBe("warn");
    expect(worstStatus(["ok", "unknown", "warn"])).toBe("unknown");
    expect(worstStatus(["crit", "unknown"])).toBe("crit");
    expect(worstStatus(["ok", "ok"])).toBe("ok");
    expect(worstStatus([])).toBe("ok");
  });
});

describe("slotFor / nextCheckAt", () => {
  it("aligns the slot to the interval boundary", () => {
    const now = new Date("2026-09-03T04:37:11.000Z");
    expect(slotFor(now, 21600)).toBe("2026-09-03T00:00:00.000Z"); // 6h slots
    expect(slotFor(now, 3600)).toBe("2026-09-03T04:00:00.000Z"); // 1h slots
  });

  it("schedules within [now+interval, now+interval*(1+jitter)]", () => {
    const now = new Date("2026-09-03T00:00:00.000Z");
    for (let i = 0; i < 50; i++) {
      const t = new Date(nextCheckAt(now, 3600, 0.1)).getTime();
      expect(t).toBeGreaterThanOrEqual(now.getTime() + 3600_000);
      expect(t).toBeLessThanOrEqual(now.getTime() + 3600_000 * 1.1 + 1);
    }
  });
});
