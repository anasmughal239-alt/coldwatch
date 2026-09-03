/**
 * Shared vocabulary for every check. A check never throws for a "the record is
 * bad" condition — that is a `Finding`. It only produces an `unknown` status
 * when it genuinely could not determine the answer (resolver/network failure).
 */

export type Severity = "ok" | "info" | "warn" | "crit" | "unknown";

export type CheckType = "spf" | "dmarc" | "dkim" | "mx" | "blacklist";

export interface Finding {
  /** Stable machine-readable code, e.g. "spf.too_many_lookups". */
  code: string;
  severity: Severity;
  /** One-line human summary. */
  title: string;
  /** Specifics for this domain (counts, offending token, chain...). */
  detail?: string;
  /** Concrete remediation. */
  fix?: string;
}

export interface CheckResult {
  check: CheckType;
  /** Worst severity across `findings`, per `rollup`. */
  status: Severity;
  findings: Finding[];
  /** Parsed record + intermediate data, surfaced in JSON output / the UI. */
  data: Record<string, unknown>;
}

const RANK: Record<Severity, number> = {
  ok: 0,
  info: 1,
  warn: 2,
  unknown: 3,
  crit: 4,
};

/**
 * Roll a list of findings up to a single status.
 * `crit` always wins (the domain is definitely broken); otherwise `unknown`
 * outranks `warn` so an undeterminable check is never reported as a soft pass.
 */
export function rollup(findings: Finding[]): Severity {
  let worst: Severity = "ok";
  for (const f of findings) {
    if (RANK[f.severity] > RANK[worst]) worst = f.severity;
  }
  return worst;
}

export function result(
  check: CheckType,
  findings: Finding[],
  data: Record<string, unknown> = {},
): CheckResult {
  return { check, status: rollup(findings), findings, data };
}
