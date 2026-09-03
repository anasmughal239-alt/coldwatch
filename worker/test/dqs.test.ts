import { describe, expect, it } from "vitest";
import type { DnsOutcome, Resolver } from "../../src/index.js";
import { dqsQueryName } from "../src/dnsbl.js";
import {
  DqsClient,
  type CachedVerdict,
  type DqsBudgetStore,
  type DqsCacheStore,
} from "../src/dqs.js";

class FakeCache implements DqsCacheStore {
  map = new Map<string, CachedVerdict>();
  async getVerdict(zone: string, entity: string, nowIso: string) {
    const v = this.map.get(`${zone}|${entity}`);
    return v && v.expiresAt > nowIso ? v : null;
  }
  async putVerdict(
    zone: string,
    entity: string,
    v: { status: "ok" | "listed"; listed: boolean; lists: string[] },
    _checkedAtIso: string,
    expiresAtIso: string,
  ) {
    this.map.set(`${zone}|${entity}`, { ...v, expiresAt: expiresAtIso });
  }
}

class FakeBudget implements DqsBudgetStore {
  reservations: number[] = [];
  constructor(public remaining: number) {}
  async reserveBudget(_day: string, cost: number) {
    this.reservations.push(cost);
    if (cost > this.remaining) return false;
    this.remaining -= cost;
    return true;
  }
}

function resolverFrom(map: Record<string, DnsOutcome>): Resolver & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    async query(name: string): Promise<DnsOutcome> {
      calls.push(name);
      return map[name] ?? { kind: "nxdomain" };
    },
  };
}

const KEY = "testkey";
const NOW = new Date("2026-09-03T00:00:00.000Z");
const zenName = (ip: string) => dqsQueryName(KEY, ip, "zen");

function client(
  resolver: Resolver,
  cache: FakeCache,
  budget: FakeBudget,
): DqsClient {
  return new DqsClient({
    key: KEY,
    resolver,
    cache,
    budget,
    dailyCeiling: 1000,
    now: () => NOW,
  });
}

describe("DqsClient", () => {
  it("serves a cache hit without touching budget or resolver", async () => {
    const cache = new FakeCache();
    cache.map.set("zen|192.0.2.7", {
      status: "ok",
      listed: false,
      lists: [],
      expiresAt: "2999-01-01T00:00:00.000Z",
    });
    const budget = new FakeBudget(0);
    const resolver = resolverFrom({});

    const r = await client(resolver, cache, budget).check("192.0.2.7", "zen");
    expect(r).toMatchObject({ status: "ok", reason: "cached" });
    expect(resolver.calls).toHaveLength(0);
    expect(budget.reservations).toHaveLength(0);
  });

  it("resolves a clean IP, spends budget, and caches it", async () => {
    const cache = new FakeCache();
    const budget = new FakeBudget(10);
    const resolver = resolverFrom({ [zenName("192.0.2.7")]: { kind: "nxdomain" } });
    const c = client(resolver, cache, budget);

    const r1 = await c.check("192.0.2.7", "zen");
    expect(r1).toMatchObject({ status: "ok", listed: false, reason: "fresh" });
    expect(budget.remaining).toBe(9);

    const r2 = await c.check("192.0.2.7", "zen");
    expect(r2.reason).toBe("cached");
    expect(budget.remaining).toBe(9); // no further spend
  });

  it("reports a listing", async () => {
    const cache = new FakeCache();
    const resolver = resolverFrom({
      [zenName("10.0.0.9")]: { kind: "answers", records: ["127.0.0.2"], ttl: 60 },
    });
    const r = await client(resolver, cache, new FakeBudget(10)).check("10.0.0.9", "zen");
    expect(r).toMatchObject({ status: "listed", listed: true, lists: ["SBL"] });
  });

  it("degrades to unknown/quota when the budget is exhausted", async () => {
    const resolver = resolverFrom({});
    const r = await client(resolver, new FakeCache(), new FakeBudget(0)).check(
      "192.0.2.7",
      "zen",
    );
    expect(r).toMatchObject({ status: "unknown", reason: "quota" });
    expect(resolver.calls).toHaveLength(0);
  });

  it("trips the breaker on a 127.255.255.x reply and stops querying", async () => {
    const resolver = resolverFrom({
      [zenName("192.0.2.7")]: {
        kind: "answers",
        records: ["127.255.255.254"],
        ttl: 60,
      },
    });
    const budget = new FakeBudget(10);
    const c = client(resolver, new FakeCache(), budget);

    const r1 = await c.check("192.0.2.7", "zen");
    expect(r1).toMatchObject({ status: "unknown", reason: "error" });
    expect(c.tripped).toBe(true);

    const before = resolver.calls.length;
    const r2 = await c.check("198.51.100.1", "zen");
    expect(r2).toMatchObject({ status: "unknown", reason: "error" });
    expect(resolver.calls.length).toBe(before); // no new query
  });

  it("trips the breaker after repeated DQS lookup errors (e.g. a dead key)", async () => {
    // resolver returns SERVFAIL-style error for everything
    const resolver: Resolver & { calls: string[] } = {
      calls: [],
      async query(name: string) {
        (resolver.calls as string[]).push(name);
        return { kind: "error", reason: "DNS rcode 2", rcode: 2 } as DnsOutcome;
      },
    };
    const budget = new FakeBudget(100);
    const c = client(resolver, new FakeCache(), budget);

    for (let i = 0; i < 3; i++) await c.check(`10.0.0.${i}`, "zen");
    expect(c.tripped).toBe(true);

    const before = resolver.calls.length;
    const r = await c.check("10.0.0.99", "zen");
    expect(r).toMatchObject({ status: "unknown", reason: "error" });
    expect(resolver.calls.length).toBe(before); // breaker short-circuits
  });

  it("reserves budget once for a batch and fails all if it won't fit", async () => {
    const budget = new FakeBudget(1);
    const resolver = resolverFrom({});
    const results = await client(resolver, new FakeCache(), budget).checkMany([
      { entity: "192.0.2.1", zone: "zen" },
      { entity: "acme.com", zone: "dbl" },
    ]);
    expect(budget.reservations).toEqual([2]);
    expect(results.every((r) => r.reason === "quota")).toBe(true);
  });
});
