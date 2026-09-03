import { describe, expect, it } from "vitest";
import type { DomainReport } from "../../src/index.js";
import { runDueChecks, type SchedulerDeps } from "../src/scheduler.js";
import type {
  DueDomain,
  ResultRow,
  RunSummary,
  SchedulerStore,
  StateWrite,
} from "../src/store.js";
import type { StateRow } from "../src/state.js";

interface Committed {
  runId: number;
  domainId: number;
  summary: RunSummary;
  results: ResultRow[];
  states: StateWrite[];
}

class FakeStore implements SchedulerStore {
  due: DueDomain[] = [];
  states = new Map<number, Map<string, StateRow>>();
  committed: Committed[] = [];
  reschedules: Array<{ id: number; next: string }> = [];
  private taken = new Set<string>();
  private nextRunId = 1;

  async getDueDomains(_nowIso: string, limit: number): Promise<DueDomain[]> {
    return this.due.slice(0, limit);
  }
  async getStates(domainId: number): Promise<Map<string, StateRow>> {
    return this.states.get(domainId) ?? new Map();
  }
  async beginRun(domainId: number, slotTs: string): Promise<number | null> {
    const key = `${domainId}:${slotTs}`;
    if (this.taken.has(key)) return null;
    this.taken.add(key);
    return this.nextRunId++;
  }
  async commitRun(args: Committed): Promise<void> {
    this.committed.push(args);
  }
  async reschedule(id: number, next: string): Promise<void> {
    this.reschedules.push({ id, next });
  }
}

function report(
  domain: string,
  statuses: Partial<Record<"spf" | "dkim" | "dmarc" | "mx", DomainReport["checks"][number]["status"]>> = {},
): DomainReport {
  const mk = (check: "spf" | "dkim" | "dmarc" | "mx") => ({
    check,
    status: statuses[check] ?? ("ok" as const),
    findings: [],
    data: {},
  });
  return {
    domain,
    checkedAt: "2026-09-03T00:00:05.000Z",
    score: 88,
    grade: "B",
    readiness: "at-risk",
    checks: [mk("spf"), mk("dkim"), mk("dmarc"), mk("mx")],
  };
}

function deps(store: FakeStore, check: SchedulerDeps["check"]): SchedulerDeps {
  return {
    store,
    check,
    now: () => new Date("2026-09-03T00:00:00.000Z"),
    batchLimit: 8,
    maxDkimProbes: 14,
    jitterFraction: 0.1,
  };
}

describe("runDueChecks", () => {
  it("checks a due domain and persists results, states and reschedule", async () => {
    const store = new FakeStore();
    store.due = [{ id: 1, domain: "acme.com", dkimSelectors: [], checkIntervalSeconds: 21600 }];

    const summary = await runDueChecks(deps(store, async (d) => report(d)));

    expect(summary).toEqual({ due: 1, checked: 1, skipped: 0, errors: 0 });
    expect(store.committed).toHaveLength(1);
    expect(store.committed[0]!.results).toHaveLength(4);
    expect(store.committed[0]!.states).toHaveLength(4);
    expect(store.committed[0]!.summary.status).toBe("ok");
    expect(store.committed[0]!.summary.error).toBeNull();
    expect(store.reschedules).toHaveLength(1);
    expect(new Date(store.reschedules[0]!.next).getTime()).toBeGreaterThan(
      Date.parse("2026-09-03T00:00:00.000Z"),
    );
  });

  it("respects the batch limit", async () => {
    const store = new FakeStore();
    store.due = Array.from({ length: 5 }, (_, i) => ({
      id: i + 1,
      domain: `d${i}.com`,
      dkimSelectors: [],
      checkIntervalSeconds: 21600,
    }));
    const d = deps(store, async (x) => report(x));
    d.batchLimit = 2;

    const summary = await runDueChecks(d);
    expect(summary.due).toBe(2);
    expect(summary.checked).toBe(2);
  });

  it("skips a slot already claimed by another run", async () => {
    const store = new FakeStore();
    store.due = [{ id: 1, domain: "acme.com", dkimSelectors: [], checkIntervalSeconds: 21600 }];
    // Pre-claim the slot for 2026-09-03T00:00:00Z / 6h interval.
    await store.beginRun(1, "2026-09-03T00:00:00.000Z");

    const summary = await runDueChecks(deps(store, async (d) => report(d)));

    expect(summary).toEqual({ due: 1, checked: 0, skipped: 1, errors: 0 });
    expect(store.committed).toHaveLength(0);
    expect(store.reschedules).toHaveLength(1);
  });

  it("records an errored run without throwing", async () => {
    const store = new FakeStore();
    store.due = [{ id: 1, domain: "acme.com", dkimSelectors: [], checkIntervalSeconds: 21600 }];

    const summary = await runDueChecks(
      deps(store, async () => {
        throw new Error("DoH exploded");
      }),
    );

    expect(summary).toEqual({ due: 1, checked: 0, skipped: 0, errors: 1 });
    expect(store.committed[0]!.summary).toMatchObject({
      status: "unknown",
      error: "DoH exploded",
    });
    expect(store.committed[0]!.results).toHaveLength(0);
    expect(store.reschedules).toHaveLength(1);
  });

  it("computes a state transition against the previous state", async () => {
    const store = new FakeStore();
    store.due = [{ id: 1, domain: "acme.com", dkimSelectors: [], checkIntervalSeconds: 21600 }];
    store.states.set(
      1,
      new Map([
        ["spf", { status: "ok", score: 90, since: "2026-09-01T00:00:00.000Z", lastOkAt: "2026-09-01T00:00:00.000Z", consecutiveCount: 9 }],
      ]),
    );

    await runDueChecks(deps(store, async (d) => report(d, { spf: "crit" })));

    const spfState = store.committed[0]!.states.find((s) => s.checkType === "spf")!;
    expect(spfState.row.status).toBe("crit");
    expect(spfState.row.consecutiveCount).toBe(1);
    expect(spfState.row.since).toBe("2026-09-03T00:00:05.000Z");
    expect(spfState.row.lastOkAt).toBe("2026-09-01T00:00:00.000Z");
  });
});
