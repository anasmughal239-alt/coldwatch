/**
 * Cron-driven check loop. Cloudflare fires `scheduled()` once per trigger and
 * never in parallel with itself, so there is no distributed-locking problem —
 * but the cron is at-least-once, so `beginRun` still guards against a
 * double-fire creating two runs for one slot.
 *
 * Domains are processed sequentially and the batch is small, keeping total DNS
 * subrequests per invocation well under the Workers free-plan cap. When that
 * ceiling is reached, the upgrade is a self-`fetch` fan-out (one sub-invocation
 * per domain) — not a rewrite.
 */

import type { CheckResult, DomainReport } from "../../src/index.js";
import type { Resolver } from "../../src/index.js";
import {
  nextCheckAt,
  nextState,
  slotFor,
  worstStatus,
  type Status,
} from "./state.js";
import type { ResultRow, SchedulerStore, StateWrite } from "./store.js";

export interface SchedulerDeps {
  store: SchedulerStore;
  check: (
    domain: string,
    opts: {
      resolver?: Resolver;
      dkimSelectors?: string[];
      maxDkimProbes?: number;
    },
  ) => Promise<DomainReport>;
  now: () => Date;
  batchLimit: number;
  maxDkimProbes: number;
  jitterFraction: number;
  makeResolver?: () => Resolver;
  /**
   * Optional blacklist stage. Given the SPF ip4/ip6 terms just observed, it
   * persists sending-IP evidence and returns a `blacklist` CheckResult (or
   * null to skip, e.g. no DQS key configured).
   */
  blacklist?: (args: {
    domainId: number;
    domain: string;
    spfIpTerms: string[];
  }) => Promise<CheckResult | null>;
  /** Recompute score/grade/readiness once the check set may include blacklist. */
  rescore?: (checks: CheckResult[]) => {
    score: number;
    grade: string;
    readiness: string;
  };
}

export interface SchedulerRunSummary {
  due: number;
  checked: number;
  skipped: number;
  errors: number;
}

export async function runDueChecks(
  deps: SchedulerDeps,
): Promise<SchedulerRunSummary> {
  const now = deps.now();
  const due = await deps.store.getDueDomains(now.toISOString(), deps.batchLimit);

  const summary: SchedulerRunSummary = {
    due: due.length,
    checked: 0,
    skipped: 0,
    errors: 0,
  };

  for (const d of due) {
    const interval = d.checkIntervalSeconds;
    const slot = slotFor(now, interval);

    const runId = await deps.store.beginRun(d.id, slot, now.toISOString());
    if (runId === null) {
      // Another invocation already handled this slot.
      summary.skipped++;
      await deps.store.reschedule(
        d.id,
        nextCheckAt(now, interval, deps.jitterFraction),
      );
      continue;
    }

    try {
      const report = await deps.check(d.domain, {
        ...(deps.makeResolver ? { resolver: deps.makeResolver() } : {}),
        dkimSelectors: d.dkimSelectors,
        maxDkimProbes: deps.maxDkimProbes,
      });

      let checks: CheckResult[] = report.checks;
      if (deps.blacklist) {
        const bl = await deps.blacklist({
          domainId: d.id,
          domain: d.domain,
          spfIpTerms: extractSpfIpTerms(report),
        });
        if (bl) checks = [...checks, bl];
      }

      const scored = deps.rescore
        ? deps.rescore(checks)
        : { score: report.score, grade: report.grade, readiness: report.readiness };

      const prev = await deps.store.getStates(d.id);
      const observedAt = report.checkedAt;
      const finishedAt = deps.now().toISOString();

      const results: ResultRow[] = checks.map((c) => ({
        checkType: c.check,
        status: c.status as Status,
        findings: JSON.stringify(c.findings),
        data: JSON.stringify(c.data ?? {}),
        observedAt,
      }));

      const states: StateWrite[] = checks.map((c) => {
        const { row } = nextState(prev.get(c.check), {
          status: c.status as Status,
          score: scored.score,
          observedAt,
        });
        return { checkType: c.check, row, lastRunId: runId, updatedAt: finishedAt };
      });

      await deps.store.commitRun({
        runId,
        domainId: d.id,
        summary: {
          status: worstStatus(checks.map((c) => c.status as Status)),
          score: scored.score,
          grade: scored.grade,
          readiness: scored.readiness,
          error: null,
          finishedAt,
        },
        results,
        states,
      });
      summary.checked++;
    } catch (err) {
      console.error(
        `scheduler: ${d.domain} run ${runId} failed:`,
        err instanceof Error ? (err.stack ?? err.message) : String(err),
      );
      try {
        await deps.store.commitRun({
          runId,
          domainId: d.id,
          summary: {
            status: "unknown",
            score: null,
            grade: null,
            readiness: null,
            error: err instanceof Error ? err.message : String(err),
            finishedAt: deps.now().toISOString(),
          },
          results: [],
          states: [],
        });
      } catch (commitErr) {
        console.error(
          `scheduler: ${d.domain} run ${runId} could not record failure:`,
          commitErr instanceof Error ? commitErr.message : String(commitErr),
        );
      }
      summary.errors++;
    }

    try {
      await deps.store.reschedule(
        d.id,
        nextCheckAt(now, interval, deps.jitterFraction),
      );
    } catch (err) {
      console.error(
        `scheduler: could not reschedule ${d.domain}:`,
        err instanceof Error ? err.message : String(err),
      );
    }
  }

  return summary;
}

function extractSpfIpTerms(report: DomainReport): string[] {
  const spf = report.checks.find((c) => c.check === "spf");
  const terms = (spf?.data as { ipTerms?: unknown } | undefined)?.ipTerms;
  return Array.isArray(terms) ? terms.filter((t): t is string => typeof t === "string") : [];
}
