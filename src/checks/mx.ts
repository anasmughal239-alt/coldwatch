/**
 * MX check + provider fingerprint. For a cold-email domain the MX matters
 * because replies and bounces have to land somewhere you can read; a domain
 * with no MX (or a "null MX") silently drops every reply.
 */

import type { Resolver } from "../dns/resolver.js";
import { parseMxRecords } from "../dns/resolver.js";
import { detectProvider, type ProviderProfile } from "../providers.js";
import { type Finding, result, type CheckResult } from "./types.js";

export interface MxCheckResult extends CheckResult {
  provider: ProviderProfile | undefined;
  exchanges: string[];
}

export async function evaluateMx(
  domain: string,
  resolver: Resolver,
): Promise<MxCheckResult> {
  const d = normalize(domain);
  const out = await resolver.query(d, "MX");

  if (out.kind === "error") {
    return withMeta(
      result(
        "mx",
        [
          {
            code: "mx.lookup_error",
            severity: "unknown",
            title: "Could not read MX records",
            detail: `DNS lookup for MX ${d} failed.`,
          },
        ],
        { domain: d },
      ),
      undefined,
      [],
    );
  }

  if (out.kind === "nxdomain" || out.kind === "nodata") {
    return withMeta(
      result(
        "mx",
        [
          {
            code: "mx.none",
            severity: "warn",
            title: "No MX records",
            detail: "Replies and bounce notifications cannot be delivered.",
            fix: "Point MX at your mailbox provider (Google Workspace, M365, ...).",
          },
        ],
        { domain: d },
      ),
      undefined,
      [],
    );
  }

  // Null MX (RFC 7505): a single record whose exchange is the root ("0 ."),
  // which some resolvers hand back as just "0".
  if (out.records.length === 1 && /^\d+\s*\.?$/.test(out.records[0]!.trim())) {
    return withMeta(
      result(
        "mx",
        [
          {
            code: "mx.null",
            severity: "warn",
            title: "Null MX — domain explicitly accepts no mail",
            detail: 'MX is "0 ." (RFC 7505).',
            fix: "Publish a real MX if this domain needs to receive replies.",
          },
        ],
        { domain: d },
      ),
      undefined,
      [],
    );
  }

  const mx = parseMxRecords(out.records);
  const exchanges = mx.map((r) => r.exchange);

  if (exchanges.length === 0) {
    return withMeta(
      result(
        "mx",
        [
          {
            code: "mx.unparseable",
            severity: "warn",
            title: "MX records could not be parsed",
            detail: out.records.join(", "),
          },
        ],
        { domain: d },
      ),
      undefined,
      [],
    );
  }

  const findings: Finding[] = [];

  const bad = exchanges.filter(
    (e) =>
      e === "localhost" ||
      e === "" ||
      /^\d+\.\d+\.\d+\.\d+$/.test(e) ||
      e.endsWith(".local") ||
      e.endsWith(".invalid"),
  );
  if (bad.length > 0) {
    findings.push({
      code: "mx.invalid_host",
      severity: "crit",
      title: "MX points at an invalid host",
      detail: bad.join(", "),
      fix: "MX must be a resolvable public hostname, not an IP or private name.",
    });
  }

  const provider = detectProvider(exchanges);
  if (provider) {
    findings.push({
      code: "mx.provider",
      severity: "ok",
      title: `Mailbox provider: ${provider.name}`,
      detail: exchanges.slice(0, 3).join(", "),
    });
  } else {
    findings.push({
      code: "mx.ok",
      severity: "ok",
      title: "MX records present",
      detail: exchanges.slice(0, 3).join(", "),
    });
  }

  return withMeta(
    result("mx", findings, {
      domain: d,
      exchanges,
      records: mx,
      provider: provider?.id ?? null,
    }),
    provider,
    exchanges,
  );
}

function withMeta(
  r: CheckResult,
  provider: ProviderProfile | undefined,
  exchanges: string[],
): MxCheckResult {
  return { ...r, provider, exchanges };
}

function normalize(domain: string): string {
  return domain
    .trim()
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "");
}
