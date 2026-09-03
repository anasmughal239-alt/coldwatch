import type { DomainReport } from "../../src/index.js";
import type { CheckResult, Finding, Severity } from "../../src/index.js";

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

const SEV_LABEL: Record<Severity, string> = {
  crit: "CRIT",
  warn: "WARN",
  unknown: "??",
  info: "INFO",
  ok: "OK",
};

const CHECK_LABEL: Record<string, string> = {
  spf: "SPF",
  dkim: "DKIM",
  dmarc: "DMARC",
  mx: "MX",
};

function finding(check: string, f: Finding): string {
  const parts = [
    `<div class="finding sev-${f.severity}">`,
    `<span class="pill">${SEV_LABEL[f.severity]}</span>`,
    `<div class="finding-body">`,
    `<div class="finding-title"><span class="check">${escapeHtml(
      CHECK_LABEL[check] ?? check,
    )}</span> ${escapeHtml(f.title)}</div>`,
    f.detail ? `<div class="finding-detail">${escapeHtml(f.detail)}</div>` : "",
    f.fix && f.severity !== "ok"
      ? `<div class="finding-fix">Fix: ${escapeHtml(f.fix)}</div>`
      : "",
    `</div></div>`,
  ];
  return parts.join("");
}

function checkBlock(c: CheckResult): string {
  const shown =
    c.findings.length > 0
      ? c.findings
      : [
          {
            code: `${c.check}.ok`,
            severity: "ok" as Severity,
            title: "No issues found",
          },
        ];
  return shown.map((f) => finding(c.check, f)).join("");
}

export function renderReport(report: DomainReport): string {
  const cls =
    report.readiness === "ready"
      ? "ready"
      : report.readiness === "at-risk"
        ? "at-risk"
        : "not-ready";

  return `
<section class="report">
  <div class="scorecard ${cls}">
    <div class="grade">${escapeHtml(report.grade)}</div>
    <div class="score-meta">
      <div class="score">${report.score}<span>/100</span></div>
      <div class="readiness">${escapeHtml(report.readiness)}</div>
      <div class="domain">${escapeHtml(report.domain)}</div>
    </div>
  </div>
  <div class="findings">
    ${report.checks.map(checkBlock).join("")}
  </div>
  <p class="checked-at">Checked ${escapeHtml(report.checkedAt)} · live DNS, nothing stored.</p>
</section>`;
}
