/**
 * Persistence layer over Cloudflare D1. The scheduler depends only on
 * `SchedulerStore`; the admin API uses the full `Store`. Tests implement the
 * small interface with an in-memory fake.
 */

import type { CachedVerdict, DqsBudgetStore, DqsCacheStore } from "./dqs.js";
import type { Zone } from "./dnsbl.js";
import type { StateRow, Status } from "./state.js";

export interface SendingIpRow {
  ip: string;
  source: string;
}

export interface DueDomain {
  id: number;
  domain: string;
  dkimSelectors: string[];
  checkIntervalSeconds: number;
}

export interface RunSummary {
  status: Status;
  score: number | null;
  grade: string | null;
  readiness: string | null;
  error: string | null;
  finishedAt: string;
}

export interface ResultRow {
  checkType: string;
  status: Status;
  findings: string; // JSON
  data: string; // JSON
  observedAt: string;
}

export interface StateWrite {
  checkType: string;
  row: StateRow;
  lastRunId: number;
  updatedAt: string;
}

export interface SchedulerStore {
  getDueDomains(nowIso: string, limit: number): Promise<DueDomain[]>;
  getStates(domainId: number): Promise<Map<string, StateRow>>;
  /** Insert the run row; returns its id, or null if the slot is already taken. */
  beginRun(
    domainId: number,
    slotTs: string,
    startedAtIso: string,
  ): Promise<number | null>;
  /** One atomic batch: results + state upserts + run finalisation. */
  commitRun(args: {
    runId: number;
    domainId: number;
    summary: RunSummary;
    results: ResultRow[];
    states: StateWrite[];
  }): Promise<void>;
  reschedule(domainId: number, nextIso: string): Promise<void>;
  getSendingIps(domainId: number): Promise<SendingIpRow[]>;
  /** Record SPF-discovered IPs; keeps existing rows' source (manual wins). */
  upsertSendingIps(
    domainId: number,
    ips: string[],
    source: string,
    nowIso: string,
  ): Promise<void>;
}

export interface DomainListRow {
  id: number;
  domain: string;
  label: string | null;
  enabled: boolean;
  checkIntervalSeconds: number;
  nextCheckAt: string;
  createdAt: string;
  lastStatus: string | null;
  lastScore: number | null;
  lastGrade: string | null;
  lastReadiness: string | null;
  lastCheckedAt: string | null;
}

export interface DomainDetail extends DomainListRow {
  dkimSelectors: string[];
  sendingIps: SendingIpRow[];
  states: Array<{
    checkType: string;
    status: string;
    score: number | null;
    since: string;
    lastOkAt: string | null;
    consecutiveCount: number;
    updatedAt: string;
  }>;
}

export interface HistoryRow {
  slotTs: string;
  startedAt: string;
  finishedAt: string | null;
  status: string | null;
  score: number | null;
  grade: string | null;
  readiness: string | null;
  error: string | null;
}

export interface AddDomainInput {
  domain: string;
  label?: string | undefined;
  dkimSelectors?: string[] | undefined;
  checkIntervalSeconds?: number | undefined;
  sendingIps?: string[] | undefined;
}

export interface Store extends SchedulerStore {
  addDomain(
    input: AddDomainInput,
    nowIso: string,
  ): Promise<{ id: number; created: boolean }>;
  removeDomain(domain: string): Promise<boolean>;
  listDomains(): Promise<DomainListRow[]>;
  getDomainDetail(domain: string): Promise<DomainDetail | null>;
  getHistory(domain: string, limit: number): Promise<HistoryRow[]>;
  getDomainId(domain: string): Promise<number | null>;
  /** Replace the `manual`-source sending IPs for a domain. */
  setManualSendingIps(
    domainId: number,
    ips: string[],
    nowIso: string,
  ): Promise<void>;
}

// ---------------------------------------------------------------------------

export class D1Store implements Store, DqsCacheStore, DqsBudgetStore {
  constructor(private readonly db: D1Database) {}

  async getDueDomains(nowIso: string, limit: number): Promise<DueDomain[]> {
    const { results } = await this.db
      .prepare(
        `SELECT id, domain, dkim_selectors, check_interval_seconds
           FROM domain
          WHERE enabled = 1 AND next_check_at <= ?
          ORDER BY next_check_at ASC
          LIMIT ?`,
      )
      .bind(nowIso, limit)
      .all<{
        id: number;
        domain: string;
        dkim_selectors: string;
        check_interval_seconds: number;
      }>();

    return (results ?? []).map((r) => ({
      id: r.id,
      domain: r.domain,
      dkimSelectors: safeJsonArray(r.dkim_selectors),
      checkIntervalSeconds: r.check_interval_seconds,
    }));
  }

  async getStates(domainId: number): Promise<Map<string, StateRow>> {
    const { results } = await this.db
      .prepare(
        `SELECT check_type, status, score, since, last_ok_at, consecutive_count
           FROM domain_check_state WHERE domain_id = ?`,
      )
      .bind(domainId)
      .all<{
        check_type: string;
        status: Status;
        score: number | null;
        since: string;
        last_ok_at: string | null;
        consecutive_count: number;
      }>();

    const map = new Map<string, StateRow>();
    for (const r of results ?? []) {
      map.set(r.check_type, {
        status: r.status,
        score: r.score,
        since: r.since,
        lastOkAt: r.last_ok_at,
        consecutiveCount: r.consecutive_count,
      });
    }
    return map;
  }

  async beginRun(
    domainId: number,
    slotTs: string,
    startedAtIso: string,
  ): Promise<number | null> {
    const row = await this.db
      .prepare(
        `INSERT INTO check_run (domain_id, slot_ts, started_at)
         VALUES (?, ?, ?)
         ON CONFLICT (domain_id, slot_ts) DO NOTHING
         RETURNING id`,
      )
      .bind(domainId, slotTs, startedAtIso)
      .first<{ id: number }>();
    return row?.id ?? null;
  }

  async commitRun(args: {
    runId: number;
    domainId: number;
    summary: RunSummary;
    results: ResultRow[];
    states: StateWrite[];
  }): Promise<void> {
    const stmts: D1PreparedStatement[] = [];

    for (const r of args.results) {
      stmts.push(
        this.db
          .prepare(
            `INSERT INTO check_result
               (run_id, domain_id, check_type, status, findings, data, observed_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
          )
          .bind(
            args.runId,
            args.domainId,
            r.checkType,
            r.status,
            r.findings,
            r.data,
            r.observedAt,
          ),
      );
    }

    for (const s of args.states) {
      stmts.push(
        this.db
          .prepare(
            `INSERT INTO domain_check_state
               (domain_id, check_type, status, score, since, last_ok_at,
                consecutive_count, last_run_id, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (domain_id, check_type) DO UPDATE SET
               status=excluded.status, score=excluded.score, since=excluded.since,
               last_ok_at=excluded.last_ok_at,
               consecutive_count=excluded.consecutive_count,
               last_run_id=excluded.last_run_id, updated_at=excluded.updated_at`,
          )
          .bind(
            args.domainId,
            s.checkType,
            s.row.status,
            s.row.score,
            s.row.since,
            s.row.lastOkAt,
            s.row.consecutiveCount,
            s.lastRunId,
            s.updatedAt,
          ),
      );
    }

    stmts.push(
      this.db
        .prepare(
          `UPDATE check_run
              SET finished_at = ?, status = ?, score = ?, grade = ?,
                  readiness = ?, error = ?
            WHERE id = ?`,
        )
        .bind(
          args.summary.finishedAt,
          args.summary.status,
          args.summary.score,
          args.summary.grade,
          args.summary.readiness,
          args.summary.error,
          args.runId,
        ),
    );

    await this.db.batch(stmts);
  }

  async reschedule(domainId: number, nextIso: string): Promise<void> {
    await this.db
      .prepare(`UPDATE domain SET next_check_at = ? WHERE id = ?`)
      .bind(nextIso, domainId)
      .run();
  }

  async getSendingIps(domainId: number): Promise<SendingIpRow[]> {
    const { results } = await this.db
      .prepare(
        `SELECT ip, source FROM domain_sending_ip WHERE domain_id = ? ORDER BY ip`,
      )
      .bind(domainId)
      .all<{ ip: string; source: string }>();
    return (results ?? []).map((r) => ({ ip: r.ip, source: r.source }));
  }

  async upsertSendingIps(
    domainId: number,
    ips: string[],
    source: string,
    nowIso: string,
  ): Promise<void> {
    const uniq = [...new Set(ips)].slice(0, 100);
    if (uniq.length === 0) return;
    await this.db.batch(
      uniq.map((ip) =>
        this.db
          .prepare(
            `INSERT INTO domain_sending_ip (domain_id, ip, source, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT (domain_id, ip) DO UPDATE SET last_seen = ?4`,
          )
          .bind(domainId, ip, source, nowIso),
      ),
    );
  }

  async setManualSendingIps(
    domainId: number,
    ips: string[],
    nowIso: string,
  ): Promise<void> {
    const uniq = [...new Set(ips)].slice(0, 100);
    const stmts: D1PreparedStatement[] = [
      this.db
        .prepare(
          `DELETE FROM domain_sending_ip WHERE domain_id = ? AND source = 'manual'`,
        )
        .bind(domainId),
    ];
    for (const ip of uniq) {
      stmts.push(
        this.db
          .prepare(
            `INSERT INTO domain_sending_ip (domain_id, ip, source, first_seen, last_seen)
             VALUES (?1, ?2, 'manual', ?3, ?3)
             ON CONFLICT (domain_id, ip) DO UPDATE SET source = 'manual', last_seen = ?3`,
          )
          .bind(domainId, ip, nowIso),
      );
    }
    await this.db.batch(stmts);
  }

  async getDomainId(domain: string): Promise<number | null> {
    const row = await this.db
      .prepare(`SELECT id FROM domain WHERE domain = ?`)
      .bind(domain)
      .first<{ id: number }>();
    return row?.id ?? null;
  }

  // --- DqsBudgetStore ---------------------------------------------------------

  async reserveBudget(
    dayUtc: string,
    cost: number,
    ceiling: number,
  ): Promise<boolean> {
    if (cost <= 0) return true;
    if (cost > ceiling) return false;
    const row = await this.db
      .prepare(
        `INSERT INTO dqs_budget (day, used) VALUES (?1, ?2)
         ON CONFLICT (day) DO UPDATE SET used = used + ?2
           WHERE used + ?2 <= ?3
         RETURNING used`,
      )
      .bind(dayUtc, cost, ceiling)
      .first<{ used: number }>();
    return row !== null;
  }

  // --- DqsCacheStore --------------------------------------------------------

  async getVerdict(
    zone: Zone,
    entity: string,
    nowIso: string,
  ): Promise<CachedVerdict | null> {
    const row = await this.db
      .prepare(
        `SELECT status, listed, lists, expires_at FROM dnsbl_cache
          WHERE zone = ?1 AND entity = ?2 AND expires_at > ?3`,
      )
      .bind(zone, entity, nowIso)
      .first<{
        status: string;
        listed: number;
        lists: string;
        expires_at: string;
      }>();
    if (!row) return null;
    return {
      status: row.status === "listed" ? "listed" : "ok",
      listed: row.listed !== 0,
      lists: safeJsonArray(row.lists),
      expiresAt: row.expires_at,
    };
  }

  async putVerdict(
    zone: Zone,
    entity: string,
    v: { status: "ok" | "listed"; listed: boolean; lists: string[] },
    checkedAtIso: string,
    expiresAtIso: string,
  ): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO dnsbl_cache
           (zone, entity, status, listed, lists, checked_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT (zone, entity) DO UPDATE SET
           status = excluded.status, listed = excluded.listed,
           lists = excluded.lists, checked_at = excluded.checked_at,
           expires_at = excluded.expires_at`,
      )
      .bind(
        zone,
        entity,
        v.status,
        v.listed ? 1 : 0,
        JSON.stringify(v.lists),
        checkedAtIso,
        expiresAtIso,
      )
      .run();
  }

  async addDomain(
    input: AddDomainInput,
    nowIso: string,
  ): Promise<{ id: number; created: boolean }> {
    const selectors = JSON.stringify(input.dkimSelectors ?? []);
    const interval = input.checkIntervalSeconds ?? 21600;
    const inserted = await this.db
      .prepare(
        `INSERT INTO domain
           (domain, label, dkim_selectors, check_interval_seconds,
            next_check_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (domain) DO NOTHING
         RETURNING id`,
      )
      .bind(
        input.domain,
        input.label ?? null,
        selectors,
        interval,
        nowIso,
        nowIso,
      )
      .first<{ id: number }>();

    const id =
      inserted?.id ??
      (
        await this.db
          .prepare(`SELECT id FROM domain WHERE domain = ?`)
          .bind(input.domain)
          .first<{ id: number }>()
      )!.id;

    if (input.sendingIps && input.sendingIps.length > 0) {
      await this.setManualSendingIps(id, input.sendingIps, nowIso);
    }

    return { id, created: Boolean(inserted) };
  }

  async removeDomain(domain: string): Promise<boolean> {
    const res = await this.db
      .prepare(`DELETE FROM domain WHERE domain = ?`)
      .bind(domain)
      .run();
    return (res.meta.changes ?? 0) > 0;
  }

  async listDomains(): Promise<DomainListRow[]> {
    const { results } = await this.db
      .prepare(
        `SELECT d.id, d.domain, d.label, d.enabled, d.check_interval_seconds,
                d.next_check_at, d.created_at,
                r.status AS last_status, r.score AS last_score,
                r.grade AS last_grade, r.readiness AS last_readiness,
                r.finished_at AS last_checked_at
           FROM domain d
           LEFT JOIN check_run r ON r.id = (
             SELECT id FROM check_run
              WHERE domain_id = d.id AND finished_at IS NOT NULL
              ORDER BY started_at DESC LIMIT 1)
          ORDER BY d.domain ASC`,
      )
      .all<Record<string, unknown>>();
    return (results ?? []).map(mapListRow);
  }

  async getDomainDetail(domain: string): Promise<DomainDetail | null> {
    const base = await this.db
      .prepare(
        `SELECT d.id, d.domain, d.label, d.enabled, d.check_interval_seconds,
                d.next_check_at, d.created_at, d.dkim_selectors,
                r.status AS last_status, r.score AS last_score,
                r.grade AS last_grade, r.readiness AS last_readiness,
                r.finished_at AS last_checked_at
           FROM domain d
           LEFT JOIN check_run r ON r.id = (
             SELECT id FROM check_run
              WHERE domain_id = d.id AND finished_at IS NOT NULL
              ORDER BY started_at DESC LIMIT 1)
          WHERE d.domain = ?`,
      )
      .bind(domain)
      .first<Record<string, unknown>>();
    if (!base) return null;

    const { results } = await this.db
      .prepare(
        `SELECT check_type, status, score, since, last_ok_at,
                consecutive_count, updated_at
           FROM domain_check_state WHERE domain_id = ?
          ORDER BY check_type`,
      )
      .bind(base.id as number)
      .all<Record<string, unknown>>();

    const sendingIps = await this.getSendingIps(base.id as number);

    return {
      ...mapListRow(base),
      dkimSelectors: safeJsonArray(String(base.dkim_selectors ?? "[]")),
      sendingIps,
      states: (results ?? []).map((s) => ({
        checkType: String(s.check_type),
        status: String(s.status),
        score: (s.score as number | null) ?? null,
        since: String(s.since),
        lastOkAt: (s.last_ok_at as string | null) ?? null,
        consecutiveCount: Number(s.consecutive_count),
        updatedAt: String(s.updated_at),
      })),
    };
  }

  async getHistory(domain: string, limit: number): Promise<HistoryRow[]> {
    const { results } = await this.db
      .prepare(
        `SELECT r.slot_ts, r.started_at, r.finished_at, r.status, r.score,
                r.grade, r.readiness, r.error
           FROM check_run r JOIN domain d ON d.id = r.domain_id
          WHERE d.domain = ?
          ORDER BY r.started_at DESC
          LIMIT ?`,
      )
      .bind(domain, limit)
      .all<Record<string, unknown>>();
    return (results ?? []).map((r) => ({
      slotTs: String(r.slot_ts),
      startedAt: String(r.started_at),
      finishedAt: (r.finished_at as string | null) ?? null,
      status: (r.status as string | null) ?? null,
      score: (r.score as number | null) ?? null,
      grade: (r.grade as string | null) ?? null,
      readiness: (r.readiness as string | null) ?? null,
      error: (r.error as string | null) ?? null,
    }));
  }
}

function mapListRow(r: Record<string, unknown>): DomainListRow {
  return {
    id: r.id as number,
    domain: String(r.domain),
    label: (r.label as string | null) ?? null,
    enabled: Boolean(r.enabled),
    checkIntervalSeconds: Number(r.check_interval_seconds),
    nextCheckAt: String(r.next_check_at),
    createdAt: String(r.created_at),
    lastStatus: (r.last_status as string | null) ?? null,
    lastScore: (r.last_score as number | null) ?? null,
    lastGrade: (r.last_grade as string | null) ?? null,
    lastReadiness: (r.last_readiness as string | null) ?? null,
    lastCheckedAt: (r.last_checked_at as string | null) ?? null,
  };
}

function safeJsonArray(s: string): string[] {
  try {
    const v = JSON.parse(s);
    return Array.isArray(v) ? v.map(String) : [];
  } catch {
    return [];
  }
}
