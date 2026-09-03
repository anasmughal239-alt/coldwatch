/**
 * Blacklist check (M3). Runs the monitored domain against Spamhaus DBL and each
 * known sending IP against ZEN, through the metered DqsClient.
 *
 * `unknown` is used honestly: a spent budget or a DQS error is reported as
 * "could not check", never as clean and never as listed.
 */

import { result } from "../../../src/checks/types.js";
import type { CheckResult, Finding } from "../../../src/checks/types.js";
import { isIndividualIp, type Zone } from "../dnsbl.js";
import type { DqsResult } from "../dqs.js";

export interface SendingIp {
  ip: string;
  source: string;
}

/** The slice of DqsClient this check needs — keeps it unit-testable. */
export interface BlacklistDqs {
  checkMany(
    targets: Array<{ entity: string; zone: Zone }>,
  ): Promise<DqsResult[]>;
}

export interface BlacklistOptions {
  /** Max sending IPs to check per domain (bounds runtime + DQS budget). */
  maxIps?: number;
}

const DEFAULT_MAX_IPS = 12;

/** Lower rank = checked first: manual-entered IPs beat SPF-derived guesses. */
function sourceRank(source: string): number {
  return { manual: 0, provider: 1, imap: 1, rua: 2, spf: 3 }[source] ?? 4;
}

export async function evaluateBlacklist(
  domain: string,
  sendingIps: SendingIp[],
  dqs: BlacklistDqs,
  opts: BlacklistOptions = {},
): Promise<CheckResult> {
  const maxIps = opts.maxIps ?? DEFAULT_MAX_IPS;
  const ranked = dedupeIps(sendingIps.filter((s) => isIndividualIp(s.ip))).sort(
    (a, b) => sourceRank(a.source) - sourceRank(b.source),
  );
  const ips = ranked.slice(0, maxIps);
  const cappedCount = ranked.length - ips.length;

  const targets: Array<{ entity: string; zone: "zen" | "dbl" }> = [
    { entity: domain, zone: "dbl" },
    ...ips.map((s) => ({ entity: stripCidr(s.ip), zone: "zen" as const })),
  ];

  const results = await dqs.checkMany(targets);
  const findings: Finding[] = [];

  const bySource = new Map(ips.map((s) => [stripCidr(s.ip), s.source]));

  for (const r of results) {
    const isDomain = r.zone === "dbl";
    const who = isDomain
      ? `Domain ${r.entity}`
      : `Sending IP ${r.entity} (${bySource.get(r.entity) ?? "unknown"} source)`;

    if (r.status === "listed") {
      findings.push({
        code: isDomain ? "blacklist.domain_listed" : "blacklist.ip_listed",
        severity: "crit",
        title: `${who} is on ${r.lists.join(", ")}`,
        detail: isDomain
          ? "Recipients using Spamhaus filtering will reject or spam-folder your mail."
          : "Mail from this IP is being blocked or spam-foldered by Spamhaus users.",
        fix: isDomain
          ? "Check https://check.spamhaus.org and request delisting once the cause is fixed."
          : "Stop sending from this IP, fix the cause, then request delisting at Spamhaus.",
      });
    } else if (r.status === "unknown") {
      findings.push({
        code: r.reason === "quota" ? "blacklist.quota" : "blacklist.error",
        severity: "unknown",
        title:
          r.reason === "quota"
            ? `${who}: not checked (daily blacklist query budget reached)`
            : `${who}: blacklist lookup failed`,
        detail:
          r.reason === "quota"
            ? "Will be retried on the next run."
            : "Temporary DQS or DNS error; retried next run.",
      });
    }
  }

  const clean = findings.every((f) => f.severity === "ok");
  if (clean) {
    const scope = ips.length
      ? `domain + ${ips.length} sending IP${ips.length > 1 ? "s" : ""}`
      : "domain (no individual sending IPs known)";
    findings.unshift({
      code: "blacklist.ok",
      severity: "ok",
      title: `Not listed — ${scope} clean`,
      ...(ips.length === 0
        ? {
            detail:
              "Add sending IPs via the API, or connect a provider, for IP-level coverage.",
          }
        : {}),
    });
  } else if (ips.length === 0) {
    findings.push({
      code: "blacklist.no_ips",
      severity: "info",
      title: "No individual sending IPs to check — domain-level only",
      detail: "Add sending IPs via the API, or connect a provider.",
    });
  }

  if (cappedCount > 0) {
    findings.push({
      code: "blacklist.ips_capped",
      severity: "info",
      title: `Checked ${ips.length} of ${ranked.length} known sending IPs`,
      detail:
        "Highest-confidence IPs (manual, then provider, then SPF) are checked first.",
    });
  }

  return result("blacklist", findings, {
    domain,
    checked: results.map((r) => ({
      entity: r.entity,
      zone: r.zone,
      status: r.status,
      lists: r.lists,
      reason: r.reason,
    })),
    ipCount: ips.length,
    knownIpCount: ranked.length,
  });
}

function dedupeIps(ips: SendingIp[]): SendingIp[] {
  const seen = new Set<string>();
  const out: SendingIp[] = [];
  for (const s of ips) {
    const k = stripCidr(s.ip);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(s);
  }
  return out;
}

function stripCidr(s: string): string {
  return s.split("/")[0]!.trim().toLowerCase();
}
