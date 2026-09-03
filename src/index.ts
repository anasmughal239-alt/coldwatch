/**
 * coldwatch — deliverability infrastructure health checks for cold-email
 * sending domains.
 *
 * Public library surface. The CLI in ./cli.ts is a thin wrapper over
 * `checkDomain`.
 */

import { DohResolver, type Resolver } from "./dns/resolver.js";
import { evaluateSpf } from "./checks/spf.js";
import { evaluateDmarc } from "./checks/dmarc.js";
import { evaluateDkim } from "./checks/dkim.js";
import { evaluateMx } from "./checks/mx.js";
import type { CheckResult } from "./checks/types.js";
import { scoreReport, type Readiness } from "./score.js";

export type { Resolver, RecordType, DnsOutcome } from "./dns/resolver.js";
export { DohResolver } from "./dns/resolver.js";
export type {
  CheckResult,
  Finding,
  Severity,
  CheckType,
} from "./checks/types.js";
export { result, rollup } from "./checks/types.js";
export { scoreReport } from "./score.js";
export type { ScoredReport, Readiness } from "./score.js";

export interface CheckDomainOptions {
  /** Inject a resolver (tests, custom endpoints). Defaults to DoH. */
  resolver?: Resolver;
  /** Known DKIM selectors to probe first. */
  dkimSelectors?: string[];
  /** Cap on DKIM selector lookups (tighten for constrained runtimes). */
  maxDkimProbes?: number;
}

export interface DomainReport {
  domain: string;
  checkedAt: string;
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  readiness: Readiness;
  checks: CheckResult[];
}

export async function checkDomain(
  domain: string,
  opts: CheckDomainOptions = {},
): Promise<DomainReport> {
  const resolver = opts.resolver ?? new DohResolver();

  // MX first: it yields the provider fingerprint that DKIM selector guessing
  // depends on.
  const mx = await evaluateMx(domain, resolver);

  const [spf, dmarc, dkim] = await Promise.all([
    evaluateSpf(domain, resolver),
    evaluateDmarc(domain, resolver),
    evaluateDkim(domain, resolver, {
      selectors: opts.dkimSelectors ?? [],
      provider: mx.provider,
      ...(opts.maxDkimProbes !== undefined
        ? { maxProbes: opts.maxDkimProbes }
        : {}),
    }),
  ]);

  const checks: CheckResult[] = [spf, dkim, dmarc, mx];
  const { score, grade, readiness } = scoreReport(checks);

  return {
    domain: normalizeDomain(domain),
    checkedAt: new Date().toISOString(),
    score,
    grade,
    readiness,
    checks,
  };
}

function normalizeDomain(domain: string): string {
  return domain
    .trim()
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "");
}
