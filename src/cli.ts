#!/usr/bin/env node
/**
 * coldwatch CLI.
 *
 *   coldwatch example.com another.com
 *   coldwatch --file domains.txt --json
 *   coldwatch example.com --selector google --selector s1
 *
 * Exit code: 0 if every domain meets the threshold (default: no `crit`
 * findings), 1 otherwise, 2 on usage error. Designed to drop into CI.
 */

import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { checkDomain, type DomainReport } from "./index.js";
import type { CheckResult, Severity } from "./checks/types.js";

const USAGE = `coldwatch — cold-email deliverability infra checks

Usage:
  coldwatch <domain> [<domain> ...] [options]

Options:
  --file <path>        Read newline-separated domains from a file
  --selector <name>    DKIM selector to probe first (repeatable)
  --json               Emit JSON instead of the text report
  --fail-on <level>    Threshold for non-zero exit: crit | warn  (default: crit)
  --concurrency <n>    Max domains checked in parallel (default: 8)
  --quiet              Only print failing checks in the text report
  -h, --help           Show this help
`;

interface Cli {
  domains: string[];
  json: boolean;
  quiet: boolean;
  failOn: "crit" | "warn";
  selectors: string[];
  concurrency: number;
}

function parse(argv: string[]): Cli {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      file: { type: "string" },
      selector: { type: "string", multiple: true },
      json: { type: "boolean", default: false },
      "fail-on": { type: "string", default: "crit" },
      concurrency: { type: "string", default: "8" },
      quiet: { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
  });

  if (values.help) {
    process.stdout.write(USAGE);
    process.exit(0);
  }

  const domains = [...positionals];
  if (values.file) {
    const text = readFileSync(values.file, "utf8");
    for (const line of text.split(/\r?\n/)) {
      const d = line.trim();
      if (d && !d.startsWith("#")) domains.push(d);
    }
  }

  if (domains.length === 0) {
    process.stderr.write(USAGE);
    process.exit(2);
  }

  const failOn = values["fail-on"] === "warn" ? "warn" : "crit";
  const concurrency = Math.max(1, Number(values.concurrency) || 8);

  return {
    domains: [...new Set(domains)],
    json: values.json ?? false,
    quiet: values.quiet ?? false,
    failOn,
    selectors: values.selector ?? [],
    concurrency,
  };
}

async function mapLimit<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const i = cursor++;
      results[i] = await fn(items[i]!);
    }
  });
  await Promise.all(workers);
  return results;
}

// --- text rendering --------------------------------------------------------

const useColor =
  process.stdout.isTTY && !process.env.NO_COLOR && process.env.TERM !== "dumb";

const c = {
  dim: (s: string) => (useColor ? `\x1b[2m${s}\x1b[0m` : s),
  bold: (s: string) => (useColor ? `\x1b[1m${s}\x1b[0m` : s),
  red: (s: string) => (useColor ? `\x1b[31m${s}\x1b[0m` : s),
  yellow: (s: string) => (useColor ? `\x1b[33m${s}\x1b[0m` : s),
  green: (s: string) => (useColor ? `\x1b[32m${s}\x1b[0m` : s),
  cyan: (s: string) => (useColor ? `\x1b[36m${s}\x1b[0m` : s),
};

function tag(sev: Severity): string {
  switch (sev) {
    case "crit":
      return c.red("CRIT");
    case "warn":
      return c.yellow("WARN");
    case "unknown":
      return c.dim(" ?? ");
    case "info":
      return c.cyan("INFO");
    case "ok":
      return c.green(" OK ");
  }
}

function renderReport(report: DomainReport, quiet: boolean): string {
  const lines: string[] = [];
  const gradeColor =
    report.readiness === "ready"
      ? c.green
      : report.readiness === "at-risk"
        ? c.yellow
        : c.red;

  lines.push("");
  const headline =
    report.readiness === "unverified"
      ? c.yellow("? · unverified — some DNS lookups failed, re-run to get a score")
      : gradeColor(`${report.grade} · ${report.score}/100 · ${report.readiness}`);
  lines.push(`${c.bold(report.domain)}  ${headline}`);

  for (const check of report.checks) {
    const shown = quiet
      ? check.findings.filter((f) => f.severity !== "ok" && f.severity !== "info")
      : check.findings;
    if (shown.length === 0) {
      lines.push(`  ${c.dim(check.check.padEnd(6))} ${tag("ok")}`);
      continue;
    }
    for (const f of shown) {
      lines.push(`  ${c.dim(check.check.padEnd(6))} [${tag(f.severity)}] ${f.title}`);
      if (f.detail) lines.push(`         ${c.dim(f.detail)}`);
      if (f.fix && f.severity !== "ok")
        lines.push(`         ${c.dim("fix: " + f.fix)}`);
    }
  }
  return lines.join("\n");
}

function worst(checks: CheckResult[]): Severity {
  const order: Severity[] = ["crit", "warn", "unknown", "info", "ok"];
  for (const s of order) if (checks.some((ch) => ch.status === s)) return s;
  return "ok";
}

// --- main ----------------------------------------------------------------

async function main(): Promise<void> {
  const cli = parse(process.argv.slice(2));

  const reports = await mapLimit(cli.domains, cli.concurrency, (d) =>
    checkDomain(d, { dkimSelectors: cli.selectors }).catch(
      (err): DomainReport => ({
        domain: d,
        checkedAt: new Date().toISOString(),
        score: 0,
        grade: "F",
        readiness: "unverified",
        checks: [
          {
            check: "spf",
            status: "unknown",
            findings: [
              {
                code: "run.error",
                severity: "unknown",
                title: "Check run failed",
                detail: err instanceof Error ? err.message : String(err),
              },
            ],
            data: {},
          },
        ],
      }),
    ),
  );

  if (cli.json) {
    process.stdout.write(JSON.stringify(reports, null, 2) + "\n");
  } else {
    for (const r of reports) process.stdout.write(renderReport(r, cli.quiet) + "\n");
    process.stdout.write("\n");
  }

  const threshold: Severity[] =
    cli.failOn === "warn" ? ["crit", "warn"] : ["crit"];
  const failed = reports.filter((r) => threshold.includes(worst(r.checks)));
  if (failed.length > 0) {
    if (!cli.json)
      process.stderr.write(
        c.red(
          `${failed.length}/${reports.length} domain(s) below threshold: ${failed
            .map((r) => r.domain)
            .join(", ")}\n`,
        ),
      );
    process.exit(1);
  }

  const unverified = reports.filter((r) => r.readiness === "unverified");
  if (unverified.length > 0) {
    if (!cli.json)
      process.stderr.write(
        c.yellow(
          `${unverified.length}/${reports.length} domain(s) could not be fully checked (DNS lookups failed): ${unverified
            .map((r) => r.domain)
            .join(", ")}\n`,
        ),
      );
    process.exit(3);
  }
}

main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.stack : String(err)}\n`);
  process.exit(2);
});
