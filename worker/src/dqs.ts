/**
 * Metered Spamhaus DQS client. One free query key serves every monitored
 * domain, so every lookup goes through:
 *
 *   cache hit?            -> 0 budget
 *   breaker open?         -> unknown/error, no query
 *   reserve daily budget  -> fail => unknown/quota, no query
 *   DNS query + parse     -> ok | listed  (cached)  |  127.255.255.x => trip breaker
 *
 * The breaker trips for the life of the instance on a `127.255.255.x` reply —
 * that means our accounting is wrong or the key is bad, and we must stop
 * hitting DQS immediately.
 */

import type { Resolver } from "../../src/index.js";
import { dqsQueryName, parseDnsbl, type Zone } from "./dnsbl.js";

export interface CachedVerdict {
  status: "ok" | "listed";
  listed: boolean;
  lists: string[];
  expiresAt: string;
}

export interface DqsCacheStore {
  getVerdict(zone: Zone, entity: string, nowIso: string): Promise<CachedVerdict | null>;
  putVerdict(
    zone: Zone,
    entity: string,
    v: { status: "ok" | "listed"; listed: boolean; lists: string[] },
    checkedAtIso: string,
    expiresAtIso: string,
  ): Promise<void>;
}

export interface DqsBudgetStore {
  /** Atomically reserve `cost` queries for `dayUtc`; false if it would exceed `ceiling`. */
  reserveBudget(dayUtc: string, cost: number, ceiling: number): Promise<boolean>;
}

export interface DqsResult {
  entity: string;
  zone: Zone;
  status: "ok" | "listed" | "unknown";
  listed: boolean;
  lists: string[];
  reason?: "cached" | "quota" | "error" | "fresh";
}

export interface DqsClientOptions {
  key: string;
  resolver: Resolver;
  cache: DqsCacheStore;
  budget: DqsBudgetStore;
  dailyCeiling: number;
  now?: () => Date;
  okTtlSeconds?: number;
  listedTtlSeconds?: number;
}

export class DqsClient {
  private readonly key: string;
  private readonly resolver: Resolver;
  private readonly cache: DqsCacheStore;
  private readonly budget: DqsBudgetStore;
  private readonly ceiling: number;
  private readonly now: () => Date;
  private readonly okTtl: number;
  private readonly listedTtl: number;
  private breakerOpen = false;
  private consecutiveErrors = 0;
  /** Trip the breaker after this many DQS lookups in a row fail outright. */
  private readonly errorBreakerThreshold = 3;

  constructor(o: DqsClientOptions) {
    this.key = o.key;
    this.resolver = o.resolver;
    this.cache = o.cache;
    this.budget = o.budget;
    this.ceiling = o.dailyCeiling;
    this.now = o.now ?? (() => new Date());
    this.okTtl = o.okTtlSeconds ?? 12 * 3600;
    this.listedTtl = o.listedTtlSeconds ?? 2 * 3600;
  }

  get tripped(): boolean {
    return this.breakerOpen;
  }

  async checkMany(
    targets: Array<{ entity: string; zone: Zone }>,
  ): Promise<DqsResult[]> {
    const now = this.now();
    const nowIso = now.toISOString();

    // 1. resolve cache hits first
    const pending: Array<{ entity: string; zone: Zone }> = [];
    const out = new Map<string, DqsResult>();
    for (const t of targets) {
      const hit = await this.cache.getVerdict(t.zone, t.entity, nowIso);
      if (hit) {
        out.set(keyOf(t), {
          entity: t.entity,
          zone: t.zone,
          status: hit.status,
          listed: hit.listed,
          lists: hit.lists,
          reason: "cached",
        });
      } else {
        pending.push(t);
      }
    }

    // 2. one budget reservation for all uncached lookups
    let haveBudget = false;
    if (pending.length > 0 && !this.breakerOpen) {
      haveBudget = await this.budget.reserveBudget(
        dayUtc(now),
        pending.length,
        this.ceiling,
      );
    }

    // 3. run the uncached lookups (or degrade them)
    for (const t of pending) {
      if (this.breakerOpen) {
        out.set(keyOf(t), degrade(t, "error"));
        continue;
      }
      if (!haveBudget) {
        out.set(keyOf(t), degrade(t, "quota"));
        continue;
      }
      out.set(keyOf(t), await this.query(t.entity, t.zone, now));
    }

    return targets.map((t) => out.get(keyOf(t))!);
  }

  async check(entity: string, zone: Zone): Promise<DqsResult> {
    const [r] = await this.checkMany([{ entity, zone }]);
    return r!;
  }

  private async query(
    entity: string,
    zone: Zone,
    now: Date,
  ): Promise<DqsResult> {
    let name: string;
    try {
      name = dqsQueryName(this.key, entity, zone);
    } catch (err) {
      return degrade({ entity, zone }, "error", errMsg(err));
    }

    const res = await this.resolver.query(name, "A");

    if (res.kind === "nxdomain" || res.kind === "nodata") {
      this.consecutiveErrors = 0;
      const v = { status: "ok" as const, listed: false, lists: [] };
      await this.storeVerdict(zone, entity, v, now);
      return { entity, zone, ...v, reason: "fresh" };
    }

    if (res.kind === "error") {
      // Resolver/network failure or SERVFAIL/REFUSED (e.g. an inactive DQS
      // key). Don't cache. Trip the breaker if it keeps happening so we stop
      // hammering a broken setup for the rest of the run.
      if (++this.consecutiveErrors >= this.errorBreakerThreshold) {
        this.breakerOpen = true;
      }
      return degrade({ entity, zone }, "error", res.reason);
    }

    const parsed = parseDnsbl(zone, res.records);
    if (parsed.error) {
      this.breakerOpen = true;
      return degrade({ entity, zone }, "error", parsed.error);
    }
    this.consecutiveErrors = 0;

    const v = {
      status: parsed.listed ? ("listed" as const) : ("ok" as const),
      listed: parsed.listed,
      lists: parsed.lists,
    };
    await this.storeVerdict(zone, entity, v, now);
    return { entity, zone, ...v, reason: "fresh" };
  }

  private async storeVerdict(
    zone: Zone,
    entity: string,
    v: { status: "ok" | "listed"; listed: boolean; lists: string[] },
    now: Date,
  ): Promise<void> {
    const ttl = v.listed ? this.listedTtl : this.okTtl;
    await this.cache.putVerdict(
      zone,
      entity,
      v,
      now.toISOString(),
      new Date(now.getTime() + ttl * 1000).toISOString(),
    );
  }
}

function degrade(
  t: { entity: string; zone: Zone },
  reason: "quota" | "error",
  _detail?: string,
): DqsResult {
  return {
    entity: t.entity,
    zone: t.zone,
    status: "unknown",
    listed: false,
    lists: [],
    reason,
  };
}

function keyOf(t: { entity: string; zone: Zone }): string {
  return `${t.zone}|${t.entity}`;
}

function dayUtc(d: Date): string {
  return d.toISOString().slice(0, 10);
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
