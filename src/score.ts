/**
 * Turn a set of check results into a single 0-100 score, a letter grade, and a
 * blunt readiness verdict. Penalties are deliberately simple and legible; the
 * findings themselves carry the nuance.
 */

import type { CheckResult, Severity } from "./checks/types.js";

const PENALTY: Record<Severity, number> = {
  crit: 35,
  warn: 10,
  unknown: 5,
  info: 2,
  ok: 0,
};

/**
 * `unverified` means a required lookup (SPF, DMARC or MX) failed, so the domain
 * could not be fully evaluated. It never counts as a pass: a DNS outage must not
 * look like a healthy domain in CI.
 */
export type Readiness = "ready" | "at-risk" | "not-ready" | "unverified";

export interface ScoredReport {
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  readiness: Readiness;
}

const MAX_INFO_DEDUCTION = 10;

export function scoreReport(checks: CheckResult[]): ScoredReport {
  let deduction = 0;
  let infoDeduction = 0;
  for (const check of checks) {
    for (const f of check.findings) {
      if (f.severity === "info") infoDeduction += PENALTY.info;
      else deduction += PENALTY[f.severity];
    }
  }
  deduction += Math.min(infoDeduction, MAX_INFO_DEDUCTION);
  const score = Math.max(0, Math.min(100, Math.round(100 - deduction)));

  const hasCrit = checks.some((c) => c.status === "crit");
  const spf = checks.find((c) => c.check === "spf");
  const dmarc = checks.find((c) => c.check === "dmarc");
  const authBroken =
    spf?.findings.some((f) => f.code === "spf.missing") ||
    dmarc?.findings.some((f) => f.code === "dmarc.missing");

  const lookupFailed = checks.some(
    (c) =>
      c.check !== "dkim" &&
      c.findings.some(
        (f) => f.code.endsWith(".lookup_error") || f.code === "run.error",
      ),
  );

  let readiness: Readiness;
  if (hasCrit || authBroken) readiness = "not-ready";
  else if (lookupFailed) readiness = "unverified";
  else if (checks.some((c) => c.status === "warn" || c.status === "unknown"))
    readiness = "at-risk";
  else readiness = "ready";

  return { score, grade: toGrade(score), readiness };
}

function toGrade(score: number): ScoredReport["grade"] {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}
