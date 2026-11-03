/**
 * SPF evaluator, faithful to the parts of RFC 7208 that actually break cold
 * email:
 *   - the 10 DNS-lookup limit (s4.6.4)          -> permerror, the #1 silent killer
 *   - the 2 "void lookup" limit (s4.6.4)         -> permerror
 *   - exactly one SPF record (s4.5)              -> permerror on 0 (for includes) / >1
 *   - the terminal `all` qualifier              -> +all is dangerous, missing is weak
 *   - deprecated `ptr` (s5.5)                    -> warn
 *   - include/redirect loops                     -> permerror
 *
 * It does NOT implement macro expansion or per-`mx` address-record counting;
 * those are noted as findings/limitations rather than fully evaluated.
 */

import type { Resolver } from "../dns/resolver.js";
import { parseMxRecords } from "../dns/resolver.js";
import { type Finding, result, type CheckResult } from "./types.js";

const MAX_LOOKUPS = 10;
const MAX_VOIDS = 2;
const MAX_MX = 10;

interface State {
  resolver: Resolver;
  lookups: number;
  voids: number;
  visited: Set<string>;
  chain: string[];
  findings: Finding[];
  sawMacro: boolean;
  ip4: number;
  ip6: number;
  /** Raw ip4:/ip6: mechanism values across the record and its includes. */
  ipTerms: string[];
  sawIncludeOrRedirect: boolean;
  limitHit: boolean;
}

interface ParsedRecord {
  all?: "+" | "-" | "~" | "?";
  redirect?: string;
}

export async function evaluateSpf(
  domain: string,
  resolver: Resolver,
): Promise<CheckResult> {
  const d = normalize(domain);
  const state: State = {
    resolver,
    lookups: 0,
    voids: 0,
    visited: new Set(),
    chain: [],
    findings: [],
    sawMacro: false,
    ip4: 0,
    ip6: 0,
    ipTerms: [],
    sawIncludeOrRedirect: false,
    limitHit: false,
  };

  const root = await walk(d, state, true);

  if (root === "resolver-error") {
    return result(
      "spf",
      [
        {
          code: "spf.lookup_error",
          severity: "unknown",
          title: "Could not read the SPF record",
          detail: `DNS lookup for TXT ${d} failed after retries.`,
        },
      ],
      { domain: d },
    );
  }

  if (root === "missing") {
    // The walk bailed. If it recorded a hard error on the way (multiple
    // records, include loop), report that rather than the generic "missing".
    if (state.findings.length > 0) {
      return result("spf", state.findings, { domain: d, chain: state.chain });
    }
    return result(
      "spf",
      [
        {
          code: "spf.missing",
          severity: "warn",
          title: "No SPF record",
          detail: `${d} publishes no "v=spf1" TXT record.`,
          fix: 'Publish a TXT record such as "v=spf1 include:<provider> -all".',
        },
      ],
      { domain: d },
    );
  }

  // root is a ParsedRecord
  const rec = root;

  if (state.lookups > MAX_LOOKUPS && !hasCode(state, "spf.too_many_lookups")) {
    // walk() normally emits this the moment the limit is crossed; this is a
    // belt-and-braces catch.
    state.findings.push(tooManyLookups(state));
  }

  if (state.voids > MAX_VOIDS) {
    state.findings.push({
      code: "spf.too_many_void_lookups",
      severity: "crit",
      title: "Too many void DNS lookups (permerror)",
      detail: `${state.voids} lookups returned NXDOMAIN/NODATA; RFC 7208 allows ${MAX_VOIDS}.`,
      fix: "Remove include: / a / mx terms that point at non-existent hosts.",
    });
  }

  if (!rec.redirect) {
    if (rec.all === undefined) {
      state.findings.push({
        code: "spf.no_all",
        severity: "warn",
        title: "No `all` mechanism",
        detail: "Receivers get no default policy for unlisted senders.",
        fix: "End the record with `-all` (or `~all` while you validate).",
      });
    } else if (rec.all === "+") {
      state.findings.push({
        code: "spf.plus_all",
        severity: "crit",
        title: "`+all` passes every sender",
        detail: "Any server on the internet passes SPF for this domain.",
        fix: "Change `+all` to `-all`.",
      });
    } else if (rec.all === "?") {
      state.findings.push({
        code: "spf.neutral_all",
        severity: "warn",
        title: "`?all` is neutral",
        detail: "Receivers treat unlisted senders as neither pass nor fail.",
        fix: "Change `?all` to `-all` once your sending sources are confirmed.",
      });
    }
  }

  if (!state.sawIncludeOrRedirect && state.ip4 + state.ip6 >= 3) {
    state.findings.push({
      code: "spf.flattened",
      severity: "info",
      title: "SPF appears flattened",
      detail: `Record is ${state.ip4 + state.ip6} literal ip4/ip6 terms with no include:.`,
      fix: "Flattened SPF breaks silently when a provider rotates IP ranges; prefer include:.",
    });
  }

  // At 9-10 lookups the record still passes, but the next tool added (most
  // include 2-4 lookups) will push it over the limit and break SPF silently.
  if (state.lookups >= MAX_LOOKUPS - 1 && state.lookups <= MAX_LOOKUPS) {
    state.findings.push({
      code: "spf.near_lookup_limit",
      severity: "warn",
      title: `SPF is at ${state.lookups}/${MAX_LOOKUPS} DNS lookups`,
      detail:
        "It passes today, but adding one more sending tool will push it over the limit and break SPF for every message.",
      fix: "Remove includes for tools you no longer use, or flatten the record, before adding another sender.",
    });
  }

  if (state.sawMacro) {
    state.findings.push({
      code: "spf.uses_macros",
      severity: "info",
      title: "SPF uses macros",
      detail: "Macro expansion (%{...}) is not fully evaluated by this check.",
    });
  }

  if (state.findings.length === 0) {
    state.findings.push({
      code: "spf.ok",
      severity: "ok",
      title: "SPF record is valid",
      detail: `${state.lookups}/${MAX_LOOKUPS} DNS lookups, ends with \`${rec.all}all\`.`,
    });
  }

  return result("spf", state.findings, {
    domain: d,
    lookups: state.lookups,
    voidLookups: state.voids,
    all: rec.all ?? null,
    redirect: rec.redirect ?? null,
    chain: state.chain,
    ipTerms: state.ipTerms,
  });
}

type WalkResult = ParsedRecord | "missing" | "resolver-error";

async function walk(
  domain: string,
  state: State,
  isRoot: boolean,
): Promise<WalkResult> {
  if (state.limitHit) return "missing";

  const key = normalize(domain);
  if (state.visited.has(key)) {
    state.findings.push({
      code: "spf.loop",
      severity: "crit",
      title: "include:/redirect= loop (permerror)",
      detail: `${key} is referenced more than once: ${[...state.chain, key].join(" -> ")}`,
      fix: "Break the circular include chain.",
    });
    return "missing";
  }
  state.visited.add(key);
  state.chain.push(key);

  const txt = await state.resolver.query(key, "TXT");

  if (txt.kind === "error") {
    if (isRoot) return "resolver-error";
    state.findings.push({
      code: "spf.include_unresolved",
      severity: "warn",
      title: `Cannot resolve include target ${key}`,
      detail: "DNS lookup failed; receivers may treat this as temperror.",
    });
    return "missing";
  }

  if (txt.kind === "nxdomain" || txt.kind === "nodata") {
    if (isRoot) return "missing";
    state.voids++;
    state.findings.push({
      code: "spf.include_void",
      severity: "warn",
      title: `include:${key} has no SPF record`,
      detail: `${txt.kind === "nxdomain" ? "Domain does not exist" : "No TXT records"}; counts as a void lookup.`,
    });
    return "missing";
  }

  const spfRecords = txt.records.filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));

  if (spfRecords.length === 0) {
    if (isRoot) return "missing";
    state.voids++;
    state.findings.push({
      code: "spf.include_no_record",
      severity: "warn",
      title: `include:${key} publishes no SPF record`,
    });
    return "missing";
  }

  if (spfRecords.length > 1) {
    state.findings.push({
      code: "spf.multiple_records",
      severity: "crit",
      title: `${key} publishes ${spfRecords.length} SPF records (permerror)`,
      detail: "RFC 7208 requires exactly one; receivers return permerror.",
      fix: "Merge them into a single \"v=spf1 ...\" TXT record.",
    });
    return "missing";
  }

  return processTerms(spfRecords[0]!, state);
}

async function processTerms(record: string, state: State): Promise<ParsedRecord> {
  const parsed: ParsedRecord = {};
  const terms = record.trim().split(/\s+/).slice(1); // drop "v=spf1"

  for (const term of terms) {
    if (state.limitHit) {
      // Past the lookup limit: do no more DNS work, but still read this
      // record's `all` so we don't misreport it as missing.
      const allTerm = /^([+\-~?]?)all$/i.exec(term);
      if (allTerm) parsed.all = (allTerm[1] || "+") as "+" | "-" | "~" | "?";
      continue;
    }
    if (term.includes("%{")) state.sawMacro = true;

    // Modifiers contain "=" and take no qualifier.
    const modifier = /^([a-z][a-z0-9_-]*)=(.*)$/i.exec(term);
    if (modifier) {
      const name = modifier[1]!.toLowerCase();
      if (name === "redirect") {
        parsed.redirect = modifier[2]!;
        state.sawIncludeOrRedirect = true;
        if (bumpLookup(state)) {
          await walk(modifier[2]!, state, false);
        }
      }
      // exp= and unknown modifiers: ignored (no DNS lookup counted for exp
      // unless SPF actually fails, which we don't simulate).
      continue;
    }

    const m = /^([+\-~?]?)([a-z][a-z0-9]*)(?::(.+))?$/i.exec(term);
    if (!m) {
      state.findings.push({
        code: "spf.syntax_error",
        severity: "crit",
        title: "Unparseable SPF term (permerror)",
        detail: `"${term}" is not a valid mechanism or modifier.`,
      });
      continue;
    }

    const qualifier = (m[1] || "+") as "+" | "-" | "~" | "?";
    const name = m[2]!.toLowerCase();
    const value = m[3];

    switch (name) {
      case "all":
        parsed.all = qualifier;
        break;

      case "include": {
        state.sawIncludeOrRedirect = true;
        if (!value) {
          state.findings.push({
            code: "spf.syntax_error",
            severity: "crit",
            title: "`include` with no domain (permerror)",
          });
          break;
        }
        if (bumpLookup(state)) await walk(value, state, false);
        break;
      }

      case "a":
      case "mx": {
        if (!bumpLookup(state)) break;
        const target = value?.split("/")[0] ?? currentDomain(state);
        await countableLookup(name, target, state);
        break;
      }

      case "ptr":
        if (!bumpLookup(state)) break;
        state.findings.push({
          code: "spf.ptr_used",
          severity: "warn",
          title: "`ptr` mechanism is deprecated",
          detail: "RFC 7208 s5.5 advises against it; slow and unreliable.",
          fix: "Remove the ptr mechanism.",
        });
        break;

      case "exists":
        bumpLookup(state);
        break;

      case "ip4":
        state.ip4++;
        if (value) state.ipTerms.push(value);
        break;
      case "ip6":
        state.ip6++;
        if (value) state.ipTerms.push(value);
        break;

      default:
        state.findings.push({
          code: "spf.unknown_mechanism",
          severity: "warn",
          title: `Unknown SPF mechanism "${name}"`,
        });
    }
  }

  return parsed;
}

async function countableLookup(
  mech: "a" | "mx",
  target: string,
  state: State,
): Promise<void> {
  if (mech === "mx") {
    const out = await state.resolver.query(target, "MX");
    if (out.kind === "nxdomain" || out.kind === "nodata") {
      state.voids++;
      return;
    }
    if (out.kind === "answers") {
      const mx = parseMxRecords(out.records);
      if (mx.length > MAX_MX) {
        state.findings.push({
          code: "spf.mx_too_many",
          severity: "crit",
          title: "`mx` resolves to more than 10 hosts (permerror)",
          detail: `${target} has ${mx.length} MX records.`,
        });
      }
    }
    return;
  }

  const a = await state.resolver.query(target, "A");
  if (a.kind === "nxdomain" || a.kind === "nodata") state.voids++;
}

function bumpLookup(state: State): boolean {
  state.lookups++;
  if (state.lookups > MAX_LOOKUPS && !state.limitHit) {
    state.limitHit = true;
    state.findings.push(tooManyLookups(state));
    return false;
  }
  return !state.limitHit;
}

function tooManyLookups(state: State): Finding {
  return {
    code: "spf.too_many_lookups",
    severity: "crit",
    title: "More than 10 DNS lookups (permerror)",
    detail:
      `Resolving this SPF record requires ${state.lookups} DNS-querying terms ` +
      `(include/a/mx/ptr/exists/redirect); RFC 7208 allows ${MAX_LOOKUPS}. ` +
      `Chain: ${state.chain.join(" -> ")}`,
    fix: "Reduce include: nesting, or use a hosted SPF-flattening service that keeps records current.",
  };
}

function currentDomain(state: State): string {
  return state.chain[state.chain.length - 1] ?? "";
}

function hasCode(state: State, code: string): boolean {
  return state.findings.some((f) => f.code === code);
}

function normalize(domain: string): string {
  return domain
    .trim()
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "");
}
