/**
 * DNS-over-HTTPS resolver with explicit NXDOMAIN / NODATA / error handling,
 * retry + provider failover, and TTL-aware in-memory caching.
 *
 * Everything downstream (SPF, DMARC, DKIM, MX evaluators) depends only on the
 * `Resolver` interface, so tests inject an in-memory mock and never touch the
 * network.
 */

export type RecordType = "A" | "AAAA" | "TXT" | "MX" | "CNAME" | "NS";

const TYPE_NUMBERS: Record<RecordType, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  MX: 15,
  TXT: 16,
  AAAA: 28,
};

/**
 * The four outcomes a lookup can have. Callers MUST distinguish `nodata`
 * (name exists, no records of this type) from `nxdomain` (name does not exist)
 * from `error` (we could not determine anything). Collapsing these is the
 * single most common source of false results in deliverability tooling.
 */
export type DnsOutcome =
  | { kind: "answers"; records: string[]; ttl: number }
  | { kind: "nodata" }
  | { kind: "nxdomain" }
  | { kind: "error"; reason: string; rcode?: number };

export interface Resolver {
  query(name: string, type: RecordType): Promise<DnsOutcome>;
}

/** A single MX record, already sorted by ascending preference. */
export interface MxRecord {
  preference: number;
  exchange: string;
}

export interface DohResolverOptions {
  /** Ordered list of DoH JSON endpoints; later entries are failover targets. */
  endpoints?: string[];
  /** Attempts per endpoint before moving to the next one. */
  retries?: number;
  /** Per-request timeout in milliseconds. */
  timeoutMs?: number;
  /** Lower bound applied to cached TTLs (seconds). */
  minTtl?: number;
  /** Upper bound applied to cached TTLs (seconds). */
  maxTtl?: number;
  /** How long negative answers (NXDOMAIN / NODATA) are cached (seconds). */
  negativeTtl?: number;
  /** Injectable clock, for tests. */
  now?: () => number;
}

interface CacheEntry {
  outcome: DnsOutcome;
  expiresAt: number;
}

const DEFAULT_ENDPOINTS = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/resolve",
];

export class DohResolver implements Resolver {
  private readonly endpoints: string[];
  private readonly retries: number;
  private readonly timeoutMs: number;
  private readonly minTtl: number;
  private readonly maxTtl: number;
  private readonly negativeTtl: number;
  private readonly now: () => number;
  private readonly cache = new Map<string, CacheEntry>();
  /** De-dupes concurrent identical lookups within one evaluation run. */
  private readonly inflight = new Map<string, Promise<DnsOutcome>>();

  constructor(opts: DohResolverOptions = {}) {
    this.endpoints = opts.endpoints ?? DEFAULT_ENDPOINTS;
    this.retries = opts.retries ?? 3;
    this.timeoutMs = opts.timeoutMs ?? 5000;
    this.minTtl = opts.minTtl ?? 60;
    this.maxTtl = opts.maxTtl ?? 3600;
    this.negativeTtl = opts.negativeTtl ?? 300;
    this.now = opts.now ?? (() => Date.now());
  }

  async query(name: string, type: RecordType): Promise<DnsOutcome> {
    const key = `${type}:${name.toLowerCase().replace(/\.$/, "")}`;

    const cached = this.cache.get(key);
    if (cached && cached.expiresAt > this.now()) return cached.outcome;

    const existing = this.inflight.get(key);
    if (existing) return existing;

    const promise = this.resolveUncached(name, type)
      .then((outcome) => {
        this.store(key, outcome);
        return outcome;
      })
      .finally(() => this.inflight.delete(key));

    this.inflight.set(key, promise);
    return promise;
  }

  private store(key: string, outcome: DnsOutcome): void {
    let ttlSeconds: number;
    if (outcome.kind === "answers") {
      ttlSeconds = clamp(outcome.ttl, this.minTtl, this.maxTtl);
    } else if (outcome.kind === "error") {
      return; // never cache errors
    } else {
      ttlSeconds = this.negativeTtl;
    }
    this.cache.set(key, { outcome, expiresAt: this.now() + ttlSeconds * 1000 });
  }

  private async resolveUncached(
    name: string,
    type: RecordType,
  ): Promise<DnsOutcome> {
    let lastError = "no endpoints configured";

    for (const endpoint of this.endpoints) {
      for (let attempt = 0; attempt < this.retries; attempt++) {
        if (attempt > 0) await sleep(backoffMs(attempt));
        try {
          const outcome = await this.fetchOnce(endpoint, name, type);
          // SERVFAIL and friends are worth retrying / failing over; the
          // definitive answers (answers / nodata / nxdomain) are not.
          if (outcome.kind === "error" && isRetryable(outcome.rcode)) {
            lastError = outcome.reason;
            continue;
          }
          return outcome;
        } catch (err) {
          lastError = err instanceof Error ? err.message : String(err);
        }
      }
    }

    return { kind: "error", reason: lastError };
  }

  private async fetchOnce(
    endpoint: string,
    name: string,
    type: RecordType,
  ): Promise<DnsOutcome> {
    const url = new URL(endpoint);
    url.searchParams.set("name", name);
    url.searchParams.set("type", String(TYPE_NUMBERS[type]));

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let res: Response;
    try {
      res = await fetch(url, {
        headers: { accept: "application/dns-json" },
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    if (!res.ok) {
      return {
        kind: "error",
        reason: `HTTP ${res.status} from ${url.host}`,
        ...(res.status >= 500 ? { rcode: 2 } : {}),
      };
    }

    const body = (await res.json()) as DohJson;
    return parseDohResponse(body, type);
  }
}

interface DohJson {
  Status: number;
  TC?: boolean;
  Answer?: Array<{ name: string; type: number; TTL?: number; data: string }>;
  Authority?: Array<{ name: string; type: number; TTL?: number; data: string }>;
}

/** DNS RCODEs. 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN. */
export function parseDohResponse(body: DohJson, type: RecordType): DnsOutcome {
  const status = body.Status;

  if (status === 3) return { kind: "nxdomain" };
  if (status !== 0) {
    return { kind: "error", reason: `DNS rcode ${status}`, rcode: status };
  }

  const wanted = TYPE_NUMBERS[type];
  const answers = (body.Answer ?? []).filter((a) => a.type === wanted);

  if (answers.length === 0) {
    // NOERROR with nothing of the requested type = NODATA. The name exists
    // (possibly only as a CNAME, or with other record types).
    return { kind: "nodata" };
  }

  const ttl = Math.min(...answers.map((a) => a.TTL ?? 300));
  const records = answers.map((a) =>
    type === "TXT" ? decodeTxt(a.data) : stripTrailingDot(unquote(a.data)),
  );

  return { kind: "answers", records, ttl };
}

/**
 * A TXT record's rdata is one or more quoted character-strings. The DoH JSON
 * form is e.g.  "\"v=spf1 include:_spf.example.com\" \" -all\"" .
 * They MUST be concatenated with no separator (RFC 7208 s3.3, RFC 1035 s3.3.14).
 */
export function decodeTxt(data: string): string {
  const segments = data.match(/"(?:[^"\\]|\\.)*"/g);
  if (!segments) return unquote(data);
  return segments.map((s) => unescapeDnsString(unquote(s))).join("");
}

function unquote(s: string): string {
  const t = s.trim();
  if (t.startsWith('"') && t.endsWith('"') && t.length >= 2) {
    return t.slice(1, -1);
  }
  return t;
}

function unescapeDnsString(s: string): string {
  // DoH escapes embedded quotes/backslashes; decimal \DDD escapes also appear.
  return s
    .replace(/\\(\d{3})/g, (_, d: string) => String.fromCharCode(parseInt(d, 10)))
    .replace(/\\(.)/g, "$1");
}

function stripTrailingDot(s: string): string {
  return s.endsWith(".") ? s.slice(0, -1) : s;
}

/** Parse & sort MX rdata strings ("10 mail.example.com."). */
export function parseMxRecords(records: string[]): MxRecord[] {
  const parsed: MxRecord[] = [];
  for (const r of records) {
    const m = /^(\d+)\s+(\S+?)\.?$/.exec(r.trim());
    if (!m) continue;
    parsed.push({ preference: Number(m[1]), exchange: m[2]!.toLowerCase() });
  }
  return parsed.sort((a, b) => a.preference - b.preference);
}

function isRetryable(rcode?: number): boolean {
  // SERVFAIL (2) and REFUSED (5) are transient / resolver-specific.
  return rcode === 2 || rcode === 5;
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n));
}

function backoffMs(attempt: number): number {
  const base = 100 * 2 ** (attempt - 1);
  return base + Math.random() * base;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
