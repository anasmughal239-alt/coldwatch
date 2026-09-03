/**
 * DMARC evaluator (RFC 7489). Covers:
 *   - policy discovery with organizational-domain tree-walk for subdomains
 *   - `v=DMARC1` uniqueness + `p=` presence/position  -> permerror
 *   - effective policy: `p=none` is the Gmail/Yahoo/Microsoft minimum but not
 *     protective; `pct<100` is partial enforcement
 *   - missing `rua` (you are flying blind, and it blocks aggregate-report
 *     ingestion later)
 *   - external RUA destination authorization (`_report._dmarc`)
 */

import { getDomain } from "tldts";
import type { Resolver } from "../dns/resolver.js";
import { type Finding, result, type CheckResult } from "./types.js";

type Policy = "none" | "quarantine" | "reject";

interface DmarcTags {
  v?: string;
  p?: string;
  sp?: string;
  pct?: string;
  rua?: string;
  ruf?: string;
  adkim?: string;
  aspf?: string;
  fo?: string;
  rf?: string;
  ri?: string;
  [k: string]: string | undefined;
}

export async function evaluateDmarc(
  domain: string,
  resolver: Resolver,
): Promise<CheckResult> {
  const d = normalize(domain);
  const org = getDomain(d) ?? d;
  const isSubdomain = org !== d;

  const primary = await lookupDmarc(d, resolver);

  if (primary.kind === "error") {
    return unknownResult(d, `DNS lookup for _dmarc.${d} failed.`);
  }

  let source: "domain" | "org" = "domain";
  let found = primary;

  if (primary.kind !== "record" && isSubdomain) {
    const parent = await lookupDmarc(org, resolver);
    if (parent.kind === "error") {
      return unknownResult(d, `DNS lookup for _dmarc.${org} failed.`);
    }
    if (parent.kind === "record") {
      source = "org";
      found = parent;
    }
  }

  if (found.kind === "multiple") {
    return result(
      "dmarc",
      [
        {
          code: "dmarc.multiple_records",
          severity: "crit",
          title: `${found.count} DMARC records published (permerror)`,
          detail: "RFC 7489 requires exactly one; receivers ignore all of them.",
          fix: 'Keep a single "v=DMARC1; p=..." TXT record at _dmarc.',
        },
      ],
      { domain: d },
    );
  }

  if (found.kind !== "record") {
    return result(
      "dmarc",
      [
        {
          code: "dmarc.missing",
          severity: "crit",
          title: "No DMARC record",
          detail: isSubdomain
            ? `Neither _dmarc.${d} nor _dmarc.${org} publishes a policy.`
            : `_dmarc.${d} publishes no "v=DMARC1" record.`,
          fix: 'Publish at least "v=DMARC1; p=none; rua=mailto:you@yourdomain".',
        },
      ],
      { domain: d },
    );
  }

  const tags = found.tags;
  const findings: Finding[] = [];

  // --- structural validation -------------------------------------------------
  const rawTags = found.raw
    .split(";")
    .map((t) => t.trim())
    .filter(Boolean);
  const firstTag = rawTags[0]?.split("=")[0]?.trim().toLowerCase();
  const secondTag = rawTags[1]?.split("=")[0]?.trim().toLowerCase();

  if (firstTag !== "v" || (tags.v ?? "").toUpperCase() !== "DMARC1") {
    findings.push({
      code: "dmarc.bad_version",
      severity: "crit",
      title: "Record does not start with v=DMARC1 (permerror)",
    });
  }
  if (!tags.p) {
    findings.push({
      code: "dmarc.no_policy_tag",
      severity: "crit",
      title: "Missing `p=` tag (permerror)",
      detail: "Without a policy tag the record is ignored entirely.",
      fix: "Add `p=none` (or stronger) as the first tag after v=DMARC1.",
    });
  } else if (secondTag && secondTag !== "p") {
    findings.push({
      code: "dmarc.policy_not_first",
      severity: "warn",
      title: "`p=` is not the first tag after v=DMARC1",
      detail: "Some receivers are strict about tag order.",
    });
  }

  // --- effective policy ----------------------------------------------------
  const effective = effectivePolicy(tags, source);
  if (tags.p) {
    if (!isPolicy(tags.p)) {
      findings.push({
        code: "dmarc.invalid_policy",
        severity: "crit",
        title: `Invalid policy value "${tags.p}"`,
      });
    } else if (effective === "none") {
      findings.push({
        code: "dmarc.policy_none",
        severity: "warn",
        title: "Policy is `p=none`",
        detail:
          source === "org"
            ? `Inherited from _dmarc.${org} (no sp= override). Meets sender requirements, but spoofed mail is still delivered.`
            : "Meets Gmail/Yahoo/Microsoft minimum, but spoofed mail is still delivered.",
        fix: "Move to `p=quarantine` then `p=reject` once aggregate reports look clean.",
      });
    } else {
      findings.push({
        code: "dmarc.policy_enforced",
        severity: "ok",
        title: `Policy is \`p=${effective}\``,
        ...(source === "org" ? { detail: `Inherited from _dmarc.${org}.` } : {}),
      });
    }
  }

  // --- partial enforcement ----------------------------------------------------
  if (tags.pct !== undefined) {
    const pct = Number(tags.pct);
    if (!Number.isInteger(pct) || pct < 0 || pct > 100) {
      findings.push({
        code: "dmarc.invalid_pct",
        severity: "warn",
        title: `Invalid pct value "${tags.pct}"`,
      });
    } else if (pct < 100 && effective !== "none") {
      findings.push({
        code: "dmarc.pct_partial",
        severity: "warn",
        title: `Policy applied to only ${pct}% of mail`,
        detail: "The remainder is treated as p=none.",
        fix: "Raise pct to 100 once you are confident in the policy.",
      });
    }
  }

  // --- reporting ------------------------------------------------------------
  if (!tags.rua) {
    findings.push({
      code: "dmarc.no_rua",
      severity: "warn",
      title: "No `rua=` aggregate-report address",
      detail: "You get no visibility into who is sending as your domain.",
      fix: "Add `rua=mailto:dmarc@yourdomain` (also required to ingest reports later).",
    });
  } else {
    await checkExternalRua(d, org, tags.rua, resolver, findings);
  }

  return result("dmarc", findings, {
    domain: d,
    source,
    record: found.raw,
    effectivePolicy: effective,
    tags,
  });
}

// -------------------------------------------------------------------------

type DmarcLookup =
  | { kind: "record"; raw: string; tags: DmarcTags }
  | { kind: "none" }
  | { kind: "multiple"; count: number }
  | { kind: "error" };

async function lookupDmarc(
  domain: string,
  resolver: Resolver,
): Promise<DmarcLookup> {
  const out = await resolver.query(`_dmarc.${domain}`, "TXT");
  if (out.kind === "error") return { kind: "error" };
  if (out.kind === "nxdomain" || out.kind === "nodata") return { kind: "none" };

  const records = out.records.filter((r) => /^v=DMARC1\s*;/i.test(r.trim()));
  if (records.length === 0) return { kind: "none" };
  if (records.length > 1) return { kind: "multiple", count: records.length };

  return { kind: "record", raw: records[0]!.trim(), tags: parseTags(records[0]!) };
}

function parseTags(record: string): DmarcTags {
  const tags: DmarcTags = {};
  for (const part of record.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim().toLowerCase();
    const val = part.slice(eq + 1).trim();
    if (key) tags[key] = val;
  }
  return tags;
}

function effectivePolicy(tags: DmarcTags, source: "domain" | "org"): Policy {
  // Evaluating a subdomain that falls back to the org record: `sp=` applies
  // if present, otherwise `p=`. Evaluating the domain's own record: `p=`.
  const p = source === "org" ? (tags.sp ?? tags.p) : tags.p;
  return isPolicy(p) ? p : "none";
}

function isPolicy(v: string | undefined): v is Policy {
  return v === "none" || v === "quarantine" || v === "reject";
}

async function checkExternalRua(
  domain: string,
  org: string,
  rua: string,
  resolver: Resolver,
  findings: Finding[],
): Promise<void> {
  const uris = rua.split(",").map((u) => u.trim());
  for (const uri of uris) {
    const mail = /^mailto:([^!\s]+)/i.exec(uri);
    if (!mail) continue;
    const at = mail[1]!.lastIndexOf("@");
    if (at === -1) continue;
    const destDomain = mail[1]!.slice(at + 1).toLowerCase();
    const destOrg = getDomain(destDomain) ?? destDomain;

    if (destOrg === org) continue; // same org domain: no authorization needed

    const authName = `${domain}._report._dmarc.${destDomain}`;
    const out = await resolver.query(authName, "TXT");
    const authorized =
      out.kind === "answers" &&
      out.records.some((r) => /^v=DMARC1/i.test(r.trim()));

    if (!authorized) {
      findings.push({
        code: "dmarc.external_rua_unauthorized",
        severity: "warn",
        title: `External report address ${destDomain} is not authorized`,
        detail: `Missing TXT "v=DMARC1" at ${authName}; ${destDomain} will silently drop your reports.`,
        fix: `Ask ${destDomain} to publish the _report._dmarc authorization record.`,
      });
    }
  }
}

function unknownResult(domain: string, detail: string): CheckResult {
  return result(
    "dmarc",
    [
      {
        code: "dmarc.lookup_error",
        severity: "unknown",
        title: "Could not read the DMARC record",
        detail,
      },
    ],
    { domain },
  );
}

function normalize(domain: string): string {
  return domain
    .trim()
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "");
}
