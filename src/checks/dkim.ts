/**
 * DKIM check. There is no way to enumerate selectors, so we probe:
 *   1. selectors the caller supplied explicitly
 *   2. the detected provider's default selectors
 *   3. a list of common selectors (only if nothing was found yet)
 *
 * "No selector found" is `unknown`, never `crit` — absence of a guessed
 * selector is not proof that DKIM is missing. A provider's *expected* selector
 * being absent is a `warn`.
 *
 * Key-size estimation from the base64 `p=` blob is approximate and labelled as
 * such; it is enough to flag 512/768-bit keys.
 */

import type { Resolver } from "../dns/resolver.js";
import { COMMON_SELECTORS, type ProviderProfile } from "../providers.js";
import { type Finding, result, type CheckResult } from "./types.js";

const DEFAULT_MAX_PROBES = 24;

export interface DkimOptions {
  selectors?: string[];
  provider?: ProviderProfile | undefined;
  /**
   * Cap on total selector lookups. Lower it where per-request subrequest
   * budgets are tight (e.g. a Cloudflare Worker on the free plan). Explicit
   * and provider selectors are always tried; the common-selector scan is what
   * gets truncated.
   */
  maxProbes?: number;
}

type SelectorSource = "explicit" | "provider" | "common";

interface FoundKey {
  selector: string;
  source: SelectorSource;
  keyType: string;
  approxBits: number | null;
  flags: string[];
  testing: boolean;
  revoked: boolean;
  /** keyType|publicKey|flags — identical across selectors means a wildcard. */
  sig: string;
}

export async function evaluateDkim(
  domain: string,
  resolver: Resolver,
  opts: DkimOptions = {},
): Promise<CheckResult> {
  const d = normalize(domain);
  const explicit = dedupe(opts.selectors ?? []);
  const providerSelectors = dedupe(opts.provider?.dkimSelectors ?? []);
  const maxProbes = Math.max(
    explicit.length + providerSelectors.length,
    opts.maxProbes ?? DEFAULT_MAX_PROBES,
  );

  const found: FoundKey[] = [];
  const tried: string[] = [];
  let hadError = false;

  const probe = async (
    selectors: string[],
    source: SelectorSource,
  ): Promise<void> => {
    for (const sel of selectors) {
      if (tried.length >= maxProbes) return;
      if (tried.includes(sel)) continue;
      tried.push(sel);
      const out = await resolver.query(`${sel}._domainkey.${d}`, "TXT");
      if (out.kind === "error") {
        hadError = true;
        continue;
      }
      if (out.kind !== "answers") continue;
      const rec = out.records.find(isDkimKey);
      if (rec) found.push(analyzeKey(sel, source, rec));
    }
  };

  await probe(explicit, "explicit");
  await probe(providerSelectors, "provider");
  if (found.length === 0) await probe(COMMON_SELECTORS, "common");

  // A `*._domainkey` wildcard makes every probed selector resolve to the same
  // record. Collapse those to one entry so the score/report isn't swamped.
  const deduped: FoundKey[] = [];
  const bySig = new Map<string, FoundKey>();
  for (const k of found) {
    const prev = bySig.get(k.sig);
    if (prev) {
      if (prev.source === "common") prev.selector = "* (wildcard)";
      continue;
    }
    bySig.set(k.sig, k);
    deduped.push(k);
  }

  const findings: Finding[] = [];

  if (found.length === 0) {
    if (providerSelectors.length > 0) {
      findings.push({
        code: "dkim.expected_missing",
        severity: "warn",
        title: `No DKIM key at ${opts.provider?.name}'s expected selector`,
        detail: `Tried ${providerSelectors.map((s) => `${s}._domainkey.${d}`).join(", ")}.`,
        fix: `Enable and publish DKIM in the ${opts.provider?.name} admin console.`,
      });
    } else {
      findings.push({
        code: "dkim.no_selector_found",
        severity: "unknown",
        title: "No DKIM key found for any known selector",
        detail:
          `Probed ${tried.length} selectors${hadError ? " (some lookups failed)" : ""}. ` +
          "DKIM may still be configured under a custom selector.",
        fix: "Provide the selector from a DKIM-Signature header (the `s=` value) of a real message.",
      });
    }
    return result("dkim", findings, {
      domain: d,
      selectorsTried: tried,
      found: [],
    });
  }

  for (const k of deduped) {
    // Selectors we only found by guessing (the common-list scan) are reported
    // at reduced severity: a revoked/weak key there is harmless unless the
    // domain actually signs with it, which we cannot know.
    const guessed = k.source === "common";
    const sig = guessed ? " (unverified selector)" : "";

    if (k.revoked) {
      findings.push({
        code: "dkim.revoked",
        severity: guessed ? "info" : "crit",
        title: `Selector "${k.selector}" is published but revoked (empty p=)${sig}`,
        detail: guessed
          ? "Harmless unless your mail is signed with this selector."
          : "Mail signed with this selector will fail DKIM.",
        fix: "Republish the public key, or remove the record and rotate the selector.",
      });
      continue;
    }
    if (k.testing) {
      findings.push({
        code: "dkim.testing_mode",
        severity: guessed ? "info" : "warn",
        title: `Selector "${k.selector}" is in test mode (t=y)${sig}`,
        detail: "Receivers are told to treat DKIM failures as if unsigned.",
        fix: "Remove `t=y` from the key record once testing is complete.",
      });
    }
    if (k.keyType === "rsa" && k.approxBits !== null && k.approxBits < 1024) {
      findings.push({
        code: "dkim.weak_key",
        severity: guessed ? "warn" : "crit",
        title: `Selector "${k.selector}" uses a ~${k.approxBits}-bit RSA key${sig}`,
        detail: "Keys under 1024 bits are rejected by major receivers.",
        fix: "Rotate to a 2048-bit key.",
      });
    } else if (k.keyType === "rsa" && k.approxBits === 1024) {
      findings.push({
        code: "dkim.rsa_1024",
        severity: guessed ? "info" : "warn",
        title: `Selector "${k.selector}" uses a 1024-bit RSA key (approx)${sig}`,
        detail: "Accepted today, but 2048-bit is the current recommendation.",
        fix: "Rotate to a 2048-bit key when convenient.",
      });
    } else {
      findings.push({
        code: "dkim.ok",
        severity: "ok",
        title: `Valid DKIM key at selector "${k.selector}"${sig}`,
        detail: `${k.keyType}${k.approxBits ? `, ~${k.approxBits}-bit` : ""}`,
      });
    }
  }

  return result("dkim", findings, {
    domain: d,
    selectorsTried: tried,
    found: deduped.map((k) => ({
      selector: k.selector,
      source: k.source,
      keyType: k.keyType,
      approxBits: k.approxBits,
      testing: k.testing,
      revoked: k.revoked,
    })),
  });
}

function isDkimKey(record: string): boolean {
  const r = record.trim().toLowerCase();
  return r.includes("p=") && (r.startsWith("v=dkim1") || r.includes("k=") || /p=[a-z0-9+/=]/i.test(record));
}

function analyzeKey(
  selector: string,
  source: SelectorSource,
  record: string,
): FoundKey {
  const tags = new Map<string, string>();
  for (const part of record.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    tags.set(part.slice(0, eq).trim().toLowerCase(), part.slice(eq + 1).trim());
  }
  const p = (tags.get("p") ?? "").replace(/\s+/g, "");
  const keyType = (tags.get("k") ?? "rsa").toLowerCase();
  const flagList = (tags.get("t") ?? "")
    .split(":")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

  return {
    selector,
    source,
    keyType,
    approxBits: p && keyType === "rsa" ? estimateRsaBits(p) : null,
    flags: flagList,
    testing: flagList.includes("y"),
    revoked: p.length === 0,
    sig: `${keyType}|${p}|${flagList.join(",")}`,
  };
}

/**
 * Estimate RSA modulus size from the base64 SubjectPublicKeyInfo length.
 * 1024-bit SPKI ~= 160-180 bytes, 2048-bit ~= 290-300 bytes, 4096-bit ~= 550.
 */
export function estimateRsaBits(base64: string): number {
  const bytes = Math.floor((base64.replace(/=+$/, "").length * 3) / 4);
  if (bytes < 100) return 512;
  if (bytes < 150) return 768;
  if (bytes < 220) return 1024;
  if (bytes < 400) return 2048;
  if (bytes < 800) return 4096;
  return 8192;
}

function dedupe(xs: string[]): string[] {
  return [...new Set(xs.map((x) => x.trim().toLowerCase()).filter(Boolean))];
}

function normalize(domain: string): string {
  return domain
    .trim()
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "");
}
